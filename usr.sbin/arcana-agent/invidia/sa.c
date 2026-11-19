/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Manually keyed security associations for an ipsec(4) interface, by
 * PF_KEY in the agent's own process (pfkey.c; Mplify 119 §10: ESP in
 * tunnel mode, ESN, ESP in UDP, the keys given, R41-R50, R55).  The two
 * SAs of a tunnel, out and in, each its SPI and keys, with the
 * interface's reqid so its policies take them; each read back once it
 * is in, and the keys never in a trace or a title.
 *
 * A vnet jail's interface the same, by PF_KEY in the jail's network
 * (the helper makes the socket there, scope.c): its SAs and policies
 * the jail's, its key pair and what was set kept on the host beside
 * the host's, named "<interface>@<jail>" (sa_ifkey()), as its faults
 * and its sdwan-key events are; a safe change put back in the jail.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <net/if.h>
#include <net/pfkeyv2.h>
#include <netinet/in.h>
#include <netipsec/ipsec.h>

#include <arpa/inet.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/pem.h>

#include <ucl.h>

#include "agent.h"

/*
 * Each tunnel end's key pair (Mplify 119 R51-R53): X25519, the private
 * half a PEM file beside the agent's kept files, 0600, never read by
 * anything but this; the public half, 32 bytes as base64, told in the
 * sdwan read for the console to pass to the far end.  The SA keys and
 * SPIs of both directions come from the agreement with the far public
 * half by HKDF-SHA256 (NIST SP 800-56A, R54), the same on both ends:
 * the end whose public half sorts lower is A, the other B, and the
 * material is laid out A to B first.  A plain tunnel's end (gre, gif,
 * geneve) has a pair too, made by the same key verb: its STAMP key is
 * derived from it the same way, salted apart (tunnel_key_derive(),
 * gula/probe_stamp.c).
 */
#define	KEY_FILE	"sdwan-key-%s.pem"
#define	NEXT_FILE	"sdwan-key-%s-next.pem"	/* the pair to come (R110) */
#define	STATE_FILE	"sdwan-sa-%s.json"	/* the SPIs set, when, for how long */
#define	HKDF_SALT	"arcana uswe v1"
#define	PUB_B64		44	/* 32 bytes as base64 */
#define	SA_REPLAY	128	/* the window, bytes: 1024 packets (R47) */
#define	NATT_PORT	4500	/* ESP in UDP's (RFC 3948) */

/* What the words say: the SAs of the two directions. */
struct sa_words {
	uint32_t	 spi_in, spi_out;
	const char	*enc, *auth;
	const char	*key_in, *key_out, *akey_in, *akey_out;
	const char	*peer;		/* derive: the far public half */
	uint32_t	 epoch;		/* derive: which keys of the pair */
	uint32_t	 lifetime;	/* seconds the keys are good for */
	int		 install;	/* 0 both directions, 1 in only, 2 out */
	bool		 encap, esn;
	bool		 next;		/* derive: from the next pair */
};

static const struct {
	const char	*name;
	int		 keylens[3];	/* hex digits allowed, 0 ends */
	bool		 aead;
	uint8_t		 alg;		/* PF_KEY's number of it */
} encs[] = {
	{ "aes-cbc", { 32, 48, 64 }, false, SADB_X_EALG_AESCBC },
	/* The key and the nonce's four bytes after it, as one. */
	{ "aes-gcm-16", { 40, 56, 72 }, true, SADB_X_EALG_AESGCM16 },
}, auths[] = {
	{ "hmac-sha1", { 40, 0, 0 }, false, SADB_AALG_SHA1HMAC },
	{ "hmac-sha2-256", { 64, 0, 0 }, false, SADB_X_AALG_SHA2_256 },
	{ "hmac-sha2-512", { 128, 0, 0 }, false, SADB_X_AALG_SHA2_512 },
};

/*
 * An interface's name as its files, faults and events have it: of a
 * vnet jail's, "ipsec0@web" (the SD-WAN's edge_file()'s way); the
 * files are the host's, beside the agent's own, in the jail nothing.
 */
static const char *
sa_ifkey(struct work *w, const char *ifname)
{

	if (w->jail == NULL || strchr(ifname, '@') != NULL)
		return (ifname);
	return (wfmt(w, "%s@%s", ifname, w->jail));
}

static const char *
key_path(struct work *w, const char *ifname, bool next)
{
	char	buf[MAXPATHLEN];

	sdwan_conf_path(wfmt(w, next ? NEXT_FILE : KEY_FILE, sa_ifkey(w,
	    ifname)), buf, sizeof(buf));
	return (wstrdup(w, buf));
}

/* The pair of an interface, read; NULL and why when there is none. */
static EVP_PKEY *
key_load(struct work *w, const char *ifname, bool next, const char **errp)
{
	EVP_PKEY	*k;
	FILE		*fp;

	if ((fp = fopen(key_path(w, ifname, next), "r")) == NULL) {
		*errp = wfmt(w, next ? "%s has no next pair yet: ipsec-sa key "
		    "next first" : "%s has no key pair yet: ipsec-sa key first",
		    ifname);
		return (NULL);
	}
	k = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);
	if (k == NULL)
		*errp = wfmt(w, "%s: the key file is not a private key", ifname);
	return (k);
}

/* The public half of a pair as base64 (44 characters); false if not X25519. */
static bool
key_public(EVP_PKEY *k, char *b64, size_t len)
{
	unsigned char	raw[32];
	size_t		 n = sizeof(raw);

	if (len < PUB_B64 + 1 || EVP_PKEY_get_raw_public_key(k, raw, &n) != 1
	    || n != sizeof(raw))
		return (false);
	EVP_EncodeBlock((unsigned char *)b64, raw, (int)n);
	return (true);
}

/*
 * An interface's pair not what it was (made, turned, put back): told as
 * sdwan-key with its public half, so that the console gives the far end
 * the half its key is derived from (a plain tunnel's STAMP key, the
 * far end's own derived anew only from it).
 */
static void
key_told(struct work *w, const char *ifname)
{
	EVP_PKEY	*k;
	const char	*e;
	char		 pub[PUB_B64 + 1], qi[6 * (32 + MAXHOSTNAMELEN) + 1];

	if (w->dry || (k = key_load(w, ifname, false, &e)) == NULL)
		return;
	if (key_public(k, pub, sizeof(pub)))
		event_add("sdwan-key", "{\"interface\":\"%s\",\"public\":"
		    "\"%s\"}", json_quote(sa_ifkey(w, ifname), qi, sizeof(qi)),
		    pub);
	EVP_PKEY_free(k);
}

/*
 * A pair made for an interface unless it has one, or its next pair made
 * anew (R110: a new pair for the keys to come); its public half.
 */
static int
key_make(struct work *w, const char *ifname, bool next, char *pub,
    size_t plen, const char **errp)
{
	EVP_PKEY	*k;
	FILE		*fp;
	const char	*path;
	int		 fd, step;

	path = key_path(w, ifname, next);
	if (next)
		(void)unlink(path);
	else if (access(path, F_OK) == 0) {
		if ((k = key_load(w, ifname, false, errp)) == NULL)
			return (-1);
		if (!key_public(k, pub, plen)) {
			EVP_PKEY_free(k);
			*errp = wfmt(w, "%s: the key is not an X25519 one", ifname);
			return (-1);
		}
		EVP_PKEY_free(k);
		return (0);
	}
	step = step_begin(w, STEP_FILE, "write", "%s", path);
	if ((k = EVP_PKEY_Q_keygen(NULL, NULL, "X25519")) == NULL) {
		step_end(w, step, false, "no key made");
		*errp = "OpenSSL made no X25519 key";
		return (-1);
	}
	if ((fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600)) == -1 || (fp =
	    fdopen(fd, "w")) == NULL) {
		step_end(w, step, false, "%s", strerror(errno));
		*errp = wfmt(w, "%s: %s", path, strerror(errno));
		EVP_PKEY_free(k);
		if (fd != -1)
			close(fd);
		return (-1);
	}
	if (PEM_write_PrivateKey(fp, k, NULL, NULL, 0, NULL, NULL) != 1) {
		fclose(fp);
		(void)unlink(path);
		step_end(w, step, false, "not written");
		*errp = wfmt(w, "%s: the key was not written", path);
		EVP_PKEY_free(k);
		return (-1);
	}
	fclose(fp);
	step_end(w, step, true, NULL);
	(void)key_public(k, pub, plen);
	EVP_PKEY_free(k);
	if (!next)
		key_told(w, ifname);
	return (0);
}

/*
 * The SA material of both directions from this end's pair and the far
 * public half: HKDF-SHA256 of the X25519 agreement, salted, with both
 * public halves in order and the epoch as the info; the keys for A to B
 * first.  *lower says this end is A.
 */
static int
key_derive(struct work *w, const char *ifname, const char *peer_b64,
    const char *salt, uint32_t epoch, bool next, unsigned char *okm,
    size_t okmlen, bool *lower, const char **errp)
{
	EVP_PKEY	*me, *far = NULL;
	EVP_PKEY_CTX	*ctx = NULL;
	EVP_KDF		*kdf;
	EVP_KDF_CTX	*kctx;
	OSSL_PARAM	 params[5];
	unsigned char	 peer[33], shared[32], info[72], mypub[32];
	char		 myb64[PUB_B64 + 1];
	size_t		 n;
	int		 len, rc = -1;

	if (strlen(peer_b64) != PUB_B64 || (len = EVP_DecodeBlock(peer,
	    (const unsigned char *)peer_b64, PUB_B64)) < 32) {
		*errp = "peer is the far end's public half, 44 characters of "
		    "base64";
		return (-1);
	}
	if ((me = key_load(w, ifname, next, errp)) == NULL)
		return (-1);
	n = sizeof(mypub);
	if (EVP_PKEY_get_raw_public_key(me, mypub, &n) != 1 || !key_public(me,
	    myb64, sizeof(myb64))) {
		EVP_PKEY_free(me);
		*errp = wfmt(w, "%s: the key is not an X25519 one", ifname);
		return (-1);
	}
	if (memcmp(mypub, peer, 32) == 0) {
		EVP_PKEY_free(me);
		*errp = "peer is this end's own public half";
		return (-1);
	}
	*lower = memcmp(mypub, peer, 32) < 0;
	far = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer, 32);
	ctx = far != NULL ? EVP_PKEY_CTX_new(me, NULL) : NULL;
	n = sizeof(shared);
	if (ctx == NULL || EVP_PKEY_derive_init(ctx) != 1 ||
	    EVP_PKEY_derive_set_peer(ctx, far) != 1 || EVP_PKEY_derive(ctx,
	    shared, &n) != 1 || n != sizeof(shared)) {
		*errp = "the agreement with the far public half failed";
		goto out;
	}
	/* info: the two public halves in order, then the epoch. */
	memcpy(info, *lower ? mypub : peer, 32);
	memcpy(info + 32, *lower ? peer : mypub, 32);
	info[64] = (unsigned char)(epoch >> 24);
	info[65] = (unsigned char)(epoch >> 16);
	info[66] = (unsigned char)(epoch >> 8);
	info[67] = (unsigned char)epoch;
	kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
	kctx = kdf != NULL ? EVP_KDF_CTX_new(kdf) : NULL;
	params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
	    (char *)(uintptr_t)"SHA256", 0);
	params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, shared,
	    sizeof(shared));
	params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
	    (char *)(uintptr_t)salt, strlen(salt));
	params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info,
	    68);
	params[4] = OSSL_PARAM_construct_end();
	if (kctx == NULL || EVP_KDF_derive(kctx, okm, okmlen, params) != 1) {
		*errp = "HKDF gave no keys";
		if (kctx != NULL)
			EVP_KDF_CTX_free(kctx);
		if (kdf != NULL)
			EVP_KDF_free(kdf);
		goto out;
	}
	EVP_KDF_CTX_free(kctx);
	EVP_KDF_free(kdf);
	rc = 0;
out:
	OPENSSL_cleanse(shared, sizeof(shared));
	if (ctx != NULL)
		EVP_PKEY_CTX_free(ctx);
	if (far != NULL)
		EVP_PKEY_free(far);
	EVP_PKEY_free(me);
	return (rc);
}

static void
hex_of(const unsigned char *raw, size_t n, char *out)
{
	static const char	digits[] = "0123456789abcdef";
	size_t			i;

	for (i = 0; i < n; i++) {
		out[2 * i] = digits[raw[i] >> 4];
		out[2 * i + 1] = digits[raw[i] & 15];
	}
	out[2 * n] = 0;
}

/* An SPI from four bytes: 256 or more. */
static uint32_t
spi_of(const unsigned char *b)
{
	uint32_t	n;

	n = (uint32_t)b[0] << 24 | (uint32_t)b[1] << 16 | (uint32_t)b[2] << 8 |
	    b[3];
	return (n < 256 ? n + 256 : n);
}

/* What an interface's SAs are, as kept beside its keys (by the name its
 * files have, sa_ifkey()'s): the SPIs set (and the next ones, between a
 * derive with next and the commit), when, and the lifetime; NULL when
 * nothing is kept. */
static ucl_object_t *
sa_state_of(struct work *w, const char *key)
{
	struct ucl_parser	*p;
	ucl_object_t		*o;
	FILE			*fp;
	char			 path[MAXPATHLEN], buf[8192];
	size_t			 n;

	sdwan_conf_path(wfmt(w, STATE_FILE, key), path, sizeof(path));
	if ((fp = fopen(path, "r")) == NULL)
		return (NULL);
	n = fread(buf, 1, sizeof(buf) - 1, fp);
	fclose(fp);
	buf[n] = '\0';
	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	o = ucl_parser_add_string(p, buf, 0) ? ucl_parser_get_object(p) :
	    NULL;
	ucl_parser_free(p);
	return (o);
}

/* An interface's of the host or of the jail w works in. */
static ucl_object_t *
sa_state_load(struct work *w, const char *ifname)
{

	return (sa_state_of(w, sa_ifkey(w, ifname)));
}

static const char	*sstr(const ucl_object_t *, const char *);
static ucl_object_t	*derive_words(const struct sa_words *);

/* A policy's selector: from src to dst (out; in, the other way). */
struct sp_sel {
	struct sockaddr_storage	 src, dst;
	uint8_t			 splen, dplen, proto;
	uint16_t		 sport, dport;
	bool			 given;
};
static const char	*sp_words(const char *const *, size_t, struct sp_sel *);

static int
sa_state_save(struct work *w, const char *ifname, const ucl_object_t *o,
    const char **errp)
{
	char	 path[MAXPATHLEN], *json;
	int	 rc;

	sdwan_conf_path(wfmt(w, STATE_FILE, sa_ifkey(w, ifname)), path,
	    sizeof(path));
	if (o == NULL) {
		(void)unlink(path);
		return (0);
	}
	/* Whole or as it was: a crash half way leaves no SPIs cut short. */
	if ((json = (char *)ucl_object_emit(o, UCL_EMIT_JSON_COMPACT)) ==
	    NULL) {
		*errp = "out of memory";
		return (-1);
	}
	if ((rc = file_replace(path, json, strlen(json), 0600)) == -1)
		*errp = wfmt(w, "%s: %s", path, strerror(errno));
	free(json);
	return (rc);
}

static uint32_t
u32(const ucl_object_t *o, const char *key)
{
	const ucl_object_t	*v;

	v = o != NULL ? ucl_object_lookup(o, key) : NULL;
	return (v == NULL ? 0 : (uint32_t)ucl_object_toint(v));
}

/* The public halves this host keeps, for the sdwan read: keys, each an
 * interface (a vnet jail's as "ipsec0@web"), its public, its next when
 * one waits, and what was set (keyed_at, lifetime, spi_in, spi_out,
 * pending). */
void
sa_keys_json(struct work *w, ucl_object_t *top)
{
	ucl_object_t	*arr, *o, *stt;
	EVP_PKEY	*k;
	DIR		*d;
	struct dirent	*de;
	FILE		*fp;
	char		 dir[MAXPATHLEN], pub[PUB_B64 + 1], *slash,
			 ifn[32 + MAXHOSTNAMELEN];
	size_t		 n;

	arr = ucl_object_typed_new(UCL_ARRAY);
	sdwan_conf_path("sdwan-key-x.pem", dir, sizeof(dir));
	if ((slash = strrchr(dir, '/')) != NULL)
		*slash = 0;
	else
		snprintf(dir, sizeof(dir), ".");
	if ((d = opendir(dir)) != NULL) {
		while ((de = readdir(d)) != NULL) {
			if (strncmp(de->d_name, "sdwan-key-", 10) != 0)
				continue;
			n = strlen(de->d_name);
			if (n < 15 || strcmp(de->d_name + n - 4, ".pem") != 0 ||
			    n - 14 >= sizeof(ifn) || (n > 19 && strcmp(de->d_name +
			    n - 9, "-next.pem") == 0))
				continue;
			snprintf(ifn, sizeof(ifn), "%.*s", (int)(n - 14),
			    de->d_name + 10);
			if ((fp = fopen(wfmt(w, "%s/%s", dir, de->d_name), "r")) ==
			    NULL)
				continue;
			k = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
			fclose(fp);
			if (k == NULL)
				continue;
			if (key_public(k, pub, sizeof(pub))) {
				o = ucl_object_typed_new(UCL_OBJECT);
				ucl_object_insert_key(o, ucl_object_fromstring(ifn),
				    "interface", 0, false);
				ucl_object_insert_key(o, ucl_object_fromstring(pub),
				    "public", 0, false);
				EVP_PKEY_free(k);
				k = NULL;
				if ((fp = fopen(wfmt(w, "%s/sdwan-key-%s-next.pem",
				    dir, ifn), "r")) != NULL) {
					k = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
					fclose(fp);
					if (k != NULL && key_public(k, pub, sizeof(pub)))
						ucl_object_insert_key(o,
						    ucl_object_fromstring(pub), "next",
						    0, false);
				}
				if ((stt = sa_state_of(w, ifn)) != NULL) {
					static const char *const nums[] = { "at",
					    "lifetime", "spi_in", "spi_out" };

					for (size_t i = 0; i < nitems(nums); i++)
						if (ucl_object_lookup(stt, nums[i]) !=
						    NULL)
							ucl_object_insert_key(o,
							    ucl_object_fromint(u32(stt,
							    nums[i])), i == 0 ? "keyed_at"
							    : nums[i], 0, false);
					ucl_object_insert_key(o, ucl_object_frombool(
					    ucl_object_lookup(stt, "next_spi_in") !=
					    NULL), "pending", 0, false);
					ucl_object_unref(stt);
				}
				ucl_array_append(arr, o);
			}
			if (k != NULL)
				EVP_PKEY_free(k);
		}
		closedir(d);
	}
	ucl_object_insert_key(top, arr, "keys", 0, false);
}

static bool
hex_ok(const char *s, const int *lens)
{
	size_t	i, n;

	if (s == NULL)
		return (false);
	n = strlen(s);
	for (i = 0; i < n; i++)
		if (!isxdigit((unsigned char)s[i]))
			return (false);
	for (i = 0; i < 3 && lens[i] != 0; i++)
		if ((size_t)lens[i] == n)
			return (true);
	return (false);
}

static bool
addr_ok(const char *s, int *af)
{
	unsigned char	raw[16];

	if (s == NULL)
		return (false);
	if (inet_pton(AF_INET, s, raw) == 1) {
		*af = AF_INET;
		return (true);
	}
	if (inet_pton(AF_INET6, s, raw) == 1) {
		*af = AF_INET6;
		return (true);
	}
	return (false);
}

/*
 * The words parsed: "spi-in n spi-out n enc a auth a key-in hex key-out
 * hex akey-in hex akey-out hex encap esn", a key's pair in either order;
 * NULL or what is wrong.
 */
static const char *
sa_parse(const struct arc_job_spec *sp, struct sa_words *w, bool derive)
{
	const char	*k, *v, *e;
	size_t		 i, j;
	unsigned long long n;

	memset(w, 0, sizeof(*w));
	for (i = 0; i < sp->names.n; i++) {
		k = sp->names.v[i];
		if (strcmp(k, "encap") == 0) {
			w->encap = true;
			continue;
		}
		if (strcmp(k, "esn") == 0) {
			w->esn = true;
			continue;
		}
		if (strcmp(k, "next") == 0) {
			if (!derive)
				return ("next is derive's: the SAs from the next "
				    "pair");
			w->next = true;
			continue;
		}
		if (i + 1 >= sp->names.n)
			return ("a word's value is missing");
		v = sp->names.v[++i];
		if (strcmp(k, "peer") == 0) {
			w->peer = v;
			continue;
		}
		if (strcmp(k, "install") == 0) {
			if (strcmp(v, "both") == 0)
				w->install = 0;
			else if (strcmp(v, "in") == 0)
				w->install = 1;
			else if (strcmp(v, "out") == 0)
				w->install = 2;
			else
				return ("install is both, in or out: the directions "
				    "set");
			continue;
		}
		if (strcmp(k, "lifetime") == 0) {
			errno = 0;
			n = strtoull(v, (char **)(uintptr_t)&e, 10);
			if (errno != 0 || e == v || *e != 0 || n < 60 || n >
			    0xffffffffULL)
				return ("a lifetime is seconds, 60 or more");
			w->lifetime = (uint32_t)n;
			continue;
		}
		if (strcmp(k, "epoch") == 0) {
			errno = 0;
			n = strtoull(v, (char **)(uintptr_t)&e, 10);
			if (errno != 0 || e == v || *e != 0 || n > 0xffffffffULL)
				return ("an epoch is a number, 0 to 4294967295");
			w->epoch = (uint32_t)n;
			continue;
		}
		if (strcmp(k, "spi-in") == 0 || strcmp(k, "spi-out") == 0) {
			errno = 0;
			n = strtoull(v, (char **)(uintptr_t)&e, 0);
			if (errno != 0 || e == v || *e != '\0' || n < 256 || n >
			    0xffffffffULL)
				return ("an SPI is a number from 256 to "
				    "4294967295, 0x for hex");
			if (k[4] == 'i')
				w->spi_in = (uint32_t)n;
			else
				w->spi_out = (uint32_t)n;
		} else if (strcmp(k, "enc") == 0)
			w->enc = v;
		else if (strcmp(k, "auth") == 0)
			w->auth = v;
		else if (strcmp(k, "key-in") == 0)
			w->key_in = v;
		else if (strcmp(k, "key-out") == 0)
			w->key_out = v;
		else if (strcmp(k, "akey-in") == 0)
			w->akey_in = v;
		else if (strcmp(k, "akey-out") == 0)
			w->akey_out = v;
		else
			return ("the words are spi-in, spi-out, enc, auth, key-in, "
			    "key-out, akey-in, akey-out, peer, epoch, encap, esn, "
			    "next, install and lifetime");
	}
	for (j = 0; j < nitems(encs); j++)
		if (w->enc != NULL && strcmp(w->enc, encs[j].name) == 0)
			break;
	if (j == nitems(encs))
		return ("enc is aes-cbc or aes-gcm-16");
	if (derive) {
		/* The far public half says the rest: SPIs and keys come
		 * from the agreement. */
		if (w->peer == NULL || strlen(w->peer) != PUB_B64)
			return ("derive takes peer, the far end's public half, 44 "
			    "characters of base64");
		if (w->spi_in != 0 || w->spi_out != 0 || w->key_in != NULL ||
		    w->key_out != NULL || w->akey_in != NULL || w->akey_out !=
		    NULL)
			return ("derive takes no SPIs or keys: they come from the "
			    "agreement");
	} else {
		if (w->peer != NULL)
			return ("peer is derive's word");
		if (w->spi_in == 0 || w->spi_out == 0 || w->spi_in == w->spi_out)
			return ("spi-in and spi-out are needed, and differ");
		if (!hex_ok(w->key_in, encs[j].keylens) || !hex_ok(w->key_out,
		    encs[j].keylens))
			return ("key-in and key-out are hex of the algorithm's "
			    "length: 32, 48 or 64 digits for aes-cbc, 40, 56 or 72 "
			    "(the nonce after the key) for aes-gcm-16");
	}
	if (encs[j].aead) {
		if (w->auth != NULL || w->akey_in != NULL || w->akey_out != NULL)
			return ("aes-gcm-16 authenticates by itself: no auth");
		return (NULL);
	}
	for (j = 0; j < nitems(auths); j++)
		if (w->auth != NULL && strcmp(w->auth, auths[j].name) == 0)
			break;
	if (j == nitems(auths))
		return ("auth is hmac-sha1, hmac-sha2-256 or hmac-sha2-512 with "
		    "aes-cbc");
	if (!derive && (!hex_ok(w->akey_in, auths[j].keylens) || !hex_ok(
	    w->akey_out, auths[j].keylens)))
		return ("akey-in and akey-out are hex of the algorithm's length: "
		    "40 digits for hmac-sha1, 64 for hmac-sha2-256, 128 for "
		    "hmac-sha2-512");
	return (NULL);
}

/* An interface named prefix and a unit, as ipsec0. */
static bool
unit_of(const char *ifn, const char *prefix)
{
	size_t	n = strlen(prefix);

	return (ifn != NULL && strncmp(ifn, prefix, n) == 0 && ifn[n] != '\0' &&
	    ifn[n + strspn(ifn + n, "0123456789")] == '\0');
}

/*
 * The STAMP key of a plain tunnel's end (PLAN-SDN-YANG 5.1.7): from its
 * pair and the far end's public half (peer_b64) as the SAs' material
 * is, salted salt, okmlen octets into okm.  0, or -1 and why.
 */
int
tunnel_key_derive(struct work *w, const char *ifname, const char *peer_b64,
    const char *salt, unsigned char *okm, size_t okmlen, const char **errp)
{
	bool	lower;

	return (key_derive(w, ifname, peer_b64, salt, 0, false, okm, okmlen,
	    &lower, errp));
}

/* What is wrong with the job, or NULL. */
const char *
sa_check(const struct arc_job_spec *sp)
{
	struct sa_words	w;
	int		af1, af2;

	if (sp->verb == NULL || (strcmp(sp->verb, "set") != 0 && strcmp(
	    sp->verb, "clear") != 0 && strcmp(sp->verb, "key") != 0 && strcmp(
	    sp->verb, "derive") != 0 && strcmp(sp->verb, "commit") != 0 &&
	    strcmp(sp->verb, "policy") != 0 && strcmp(sp->verb, "unpolicy") !=
	    0))
		return ("ipsec-sa: say key, set, derive, commit, clear, policy or "
		    "unpolicy");
	/* A pair for a plain tunnel's end too: its STAMP key's. */
	if (sp->verb != NULL && strcmp(sp->verb, "key") == 0 && (unit_of(
	    sp->interface, "gre") || unit_of(sp->interface, "gif") ||
	    unit_of(sp->interface, "geneve")))
		return (NULL);
	if (!unit_of(sp->interface, "ipsec"))
		return ("ipsec-sa: the interface is an ipsec(4) one, ipsec0 (a "
		    "key pair, a gre, gif or geneve one's too)");
	if (strcmp(sp->verb, "key") == 0) {
		for (size_t i = 0; i < sp->names.n; i++)
			if (strcmp(sp->names.v[i], "next") != 0)
				return ("ipsec-sa key takes next at most: the pair "
				    "to come");
		return (NULL);
	}
	if (!sp->has_reqid || sp->reqid < 1 || sp->reqid > 16383)
		return ("ipsec-sa: the interface's reqid, 1 to 16383");
	if (!addr_ok(sp->tunnel_local, &af1) || !addr_ok(sp->tunnel_remote,
	    &af2) || af1 != af2)
		return ("ipsec-sa: tunnel-local and tunnel-remote are the outer "
		    "addresses, of one family");
	if (strcmp(sp->verb, "clear") == 0 || strcmp(sp->verb, "commit") == 0)
		return (NULL);
	if (strcmp(sp->verb, "policy") == 0 || strcmp(sp->verb, "unpolicy") ==
	    0) {
		struct sp_sel	sel;
		const char	*e;

		if ((e = sp_words(sp->names.v, sp->names.n, &sel)) != NULL)
			return (e);
		if (!sel.given && sp->verb[0] == 'p')
			return ("ipsec-sa policy: src and dst, the selector's "
			    "prefixes");
		return (NULL);
	}
	return (sa_parse(sp, &w, strcmp(sp->verb, "derive") == 0));
}

static bool
word_next(const struct arc_job_spec *sp)
{

	for (size_t i = 0; i < sp->names.n; i++)
		if (strcmp(sp->names.v[i], "next") == 0)
			return (true);
	return (false);
}

/* An address sa_check() took, as a sockaddr. */
static void
sa_sockaddr(const char *s, struct sockaddr_storage *ss)
{
	struct sockaddr_in	*sin = (struct sockaddr_in *)ss;
	struct sockaddr_in6	*sin6 = (struct sockaddr_in6 *)ss;

	memset(ss, 0, sizeof(*ss));
	if (inet_pton(AF_INET, s, &sin->sin_addr) == 1) {
		sin->sin_len = sizeof(*sin);
		sin->sin_family = AF_INET;
	} else if (inet_pton(AF_INET6, s, &sin6->sin6_addr) == 1) {
		sin6->sin6_len = sizeof(*sin6);
		sin6->sin6_family = AF_INET6;
	}
}

static bool
sa_same_addr(const struct sockaddr_storage *a, const struct sockaddr_storage *b)
{

	if (a->ss_family != b->ss_family)
		return (false);
	if (a->ss_family == AF_INET)
		return (memcmp(&((const struct sockaddr_in *)a)->sin_addr,
		    &((const struct sockaddr_in *)b)->sin_addr,
		    sizeof(struct in_addr)) == 0);
	return (a->ss_family == AF_INET6 && memcmp(&((const struct
	    sockaddr_in6 *)a)->sin6_addr, &((const struct sockaddr_in6 *)b)->
	    sin6_addr, sizeof(struct in6_addr)) == 0);
}

static int
nibble(char c)
{

	return (c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ?
	    c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : 0);
}

/* A key's hex digits (hex_ok()'s) as bytes; how many. */
static size_t
hex_bytes(const char *hex, unsigned char *out, size_t max)
{
	size_t	n;

	for (n = 0; n < max && hex[2 * n] != '\0' && hex[2 * n + 1] != '\0';
	    n++)
		out[n] = (unsigned char)(nibble(hex[2 * n]) << 4 |
		    nibble(hex[2 * n + 1]));
	return (n);
}

/* The job's PF_KEY socket, opened at its first message. */
static int
sa_fd(struct work *w, int *fdp, const char **errp)
{

	if (*fdp == -1)
		*fdp = pfkey_open(w, errp);
	return (*fdp);
}

/*
 * The SA of spi from src to dst taken out, if one was set (spi not 0);
 * one not there is none to take out.  What went wrong is in the step
 * alone: the SA put in after it says.
 */
static void
sa_del(struct work *w, int *fdp, const char *src, const char *dst,
    uint32_t spi)
{
	struct sockaddr_storage	 s, d;
	const char		*e;
	int			 step;

	if (spi == 0)
		return;
	step = step_begin(w, STEP_SYSCALL, "PF_KEY SADB_DELETE", "%s to %s, "
	    "SPI %#x", src, dst, spi);
	if (work_dry(w, step))
		return;
	sa_sockaddr(src, &s);
	sa_sockaddr(dst, &d);
	e = NULL;
	if (sa_fd(w, fdp, &e) == -1 || pfkey_delete(w, *fdp, (struct sockaddr *)
	    &s, (struct sockaddr *)&d, spi, &e) == -1)
		step_end(w, step, errno == ESRCH, "%s to %s, SPI %#x: %s", src,
		    dst, spi, errno == ESRCH ? "none there" : e);
	else
		step_end(w, step, true, NULL);
}

struct sa_between {
	struct sockaddr_storage	 a, b;
	uint32_t		 spi[64];
	bool			 fwd[64];	/* from a to b */
	size_t			 n;
};

static void
sa_between_one(const struct pfkey_sa *sa, void *arg)
{
	struct sa_between	*sb = arg;
	bool			 fwd;

	/* RFC 9061's lists' own (ikeless.c) are the controller's. */
	if (ikeless_sa_name(&sa->dst, sa->spi, NULL, 0))
		return;
	if ((fwd = sa_same_addr(&sa->src, &sb->a) && sa_same_addr(&sa->dst,
	    &sb->b)) || (sa_same_addr(&sa->src, &sb->b) &&
	    sa_same_addr(&sa->dst, &sb->a))) {
		if (sb->n < nitems(sb->spi)) {
			sb->spi[sb->n] = sa->spi;
			sb->fwd[sb->n++] = fwd;
		}
	}
}

/*
 * Every ESP SA between a and b, either way, taken out: those the
 * kernel has (SADB_DUMP), each by its SPI, but the IKE-less lists'
 * (ikeless.c).  -1 when they could not be read.
 */
static int
sa_clear(struct work *w, int *fdp, const char *a, const char *b)
{
	struct sa_between	 sb;
	const char		*e;
	char			*spis;
	size_t			 i;
	int			 step;

	step = step_begin(w, STEP_SYSCALL, "PF_KEY SADB_DUMP", "the SAs "
	    "between %s and %s", a, b);
	if (work_dry(w, step))
		return (0);
	memset(&sb, 0, sizeof(sb));
	sa_sockaddr(a, &sb.a);
	sa_sockaddr(b, &sb.b);
	e = NULL;
	if (sa_fd(w, fdp, &e) == -1 || pfkey_dump(w, *fdp, sa_between_one,
	    &sb, &e) == -1) {
		step_end(w, step, false, "%s", e);
		return (-1);
	}
	spis = wstrdup(w, "");
	for (i = 0; i < sb.n; i++)
		spis = wfmt(w, "%s %#x", spis, sb.spi[i]);
	step_end(w, step, true, "between %s and %s: %s%s", a, b, sb.n == 0 ?
	    "none" : "SPI", spis);
	for (i = 0; i < sb.n; i++)
		sa_del(w, fdp, sb.fwd[i] ? a : b, sb.fwd[i] ? b : a, sb.spi[i]);
	return (0);
}

/*
 * One SA put in: ESP in tunnel mode on the interface's reqid, with an
 * anti-replay window of 1024 packets (R47) always: ESN without one has
 * the kernel's two ends disagree on the AAD of an AEAD cipher
 * (xform_esp.c, the window checked on input only), and every ICV
 * fails.  The sequence number may wrap (SADB_X_EXT_CYCSEQ), as
 * setkey(8)'s SAs' may.  Read back once in (SADB_GET): the kernel has
 * it as asked, mature, or the job fails (an AEAD cipher's
 * authentication is the kernel's to name: AES-GCM's GMAC, xform_esp.c).
 */
static int
sa_put(struct work *w, int *fdp, const struct sa_words *sw, uint32_t reqid,
    const char *src, const char *dst, uint32_t spi, const char *key,
    const char *akey, const char **errp)
{
	struct pfkey_sa	 sa, got;
	unsigned char	 ek[64], ak[64];
	const char	*bad;
	size_t		 j;
	int		 step, rc;

	step = step_begin(w, STEP_SYSCALL, "PF_KEY SADB_ADD", "%s to %s, SPI "
	    "%#x, reqid %u", src, dst, spi, reqid);
	if (work_dry(w, step))
		return (0);
	memset(&sa, 0, sizeof(sa));
	sa_sockaddr(src, &sa.src);
	sa_sockaddr(dst, &sa.dst);
	sa.spi = spi;
	sa.reqid = reqid;
	sa.mode = IPSEC_MODE_TUNNEL;
	sa.replay = SA_REPLAY;
	sa.flags = SADB_X_EXT_CYCSEQ | (sw->esn ? SADB_X_SAFLAGS_ESN : 0);
	for (j = 0; j < nitems(encs); j++)
		if (strcmp(sw->enc, encs[j].name) == 0)
			sa.ealg = encs[j].alg;
	sa.aalg = SADB_AALG_NONE;
	for (j = 0; sw->auth != NULL && j < nitems(auths); j++)
		if (strcmp(sw->auth, auths[j].name) == 0)
			sa.aalg = auths[j].alg;
	sa.ekeylen = hex_bytes(key, ek, sizeof(ek));
	sa.ekey = ek;
	if (sw->auth != NULL && akey != NULL) {
		sa.akeylen = hex_bytes(akey, ak, sizeof(ak));
		sa.akey = ak;
	}
	if (sw->encap) {
		sa.natt = true;
		sa.sport = sa.dport = NATT_PORT;
	}
	rc = sa_fd(w, fdp, errp) == -1 ? -1 : pfkey_add(w, *fdp, &sa, errp);
	OPENSSL_cleanse(ek, sizeof(ek));
	OPENSSL_cleanse(ak, sizeof(ak));
	if (rc == 0)
		rc = pfkey_get(w, *fdp, (struct sockaddr *)&sa.src,
		    (struct sockaddr *)&sa.dst, spi, &got, errp);
	if (rc != 0) {
		*errp = wfmt(w, "%s to %s, SPI %#x: %s", src, dst, spi, *errp);
		step_end(w, step, false, "%s", *errp);
		return (-1);
	}
	bad = got.spi != spi ? "another SPI" : got.state !=
	    SADB_SASTATE_MATURE ? "not mature" : got.reqid != reqid ?
	    "another reqid" : got.mode != IPSEC_MODE_TUNNEL ? "not in tunnel "
	    "mode" : got.replay != SA_REPLAY ? "another replay window" :
	    (got.flags & SADB_X_SAFLAGS_ESN) != (sa.flags &
	    SADB_X_SAFLAGS_ESN) ? (sw->esn ? "no ESN" : "ESN") : got.ealg !=
	    sa.ealg || (sa.aalg != SADB_AALG_NONE && got.aalg != sa.aalg) ?
	    "other algorithms" : got.natt !=
	    sa.natt ? (sa.natt ? "no ESP in UDP" : "ESP in UDP") : NULL;
	if (bad != NULL) {
		*errp = wfmt(w, "%s to %s, SPI %#x: the kernel has it with %s",
		    src, dst, spi, bad);
		step_end(w, step, false, "%s", *errp);
		return (-1);
	}
	step_end(w, step, true, "%s to %s, SPI %#x, reqid %u: read back: "
	    "mature, a window of %u packets%s%s", src, dst, spi, reqid,
	    got.replay * 8, got.flags & SADB_X_SAFLAGS_ESN ? ", ESN" : "",
	    got.natt ? ", ESP in UDP" : "");
	return (0);
}

/* ---- Policies ------------------------------------------------------- */

/*
 * The SPD by PF_KEY (pfkey.c).  An ipsec(4) interface has policies of
 * its own, scoped to it (IPSEC_POLICYSCOPE_IFNET), on its reqid: its
 * SAs serve them and no others, so the SAs set for it go on that reqid
 * (the mapping, read from them).  Arcana's own policies send traffic of
 * a selector more through an interface's SAs, both ways (policy): global,
 * ESP in tunnel mode between the tunnel's ends, of the priority
 * PFKEY_SP_MARK, after setkey's and ipsec.conf's (0); out at level
 * unique on the reqid, so it leaves by those SAs or not at all; in at
 * level use: the kernel hands ESP of an interface's reqid to the
 * interface (if_ipsec's ipsec_if_input()) and a unique in policy then
 * refuses what came through (ipsecstat's in_polvio; measured), as it
 * would the interface's own traffic.  A policy is Arcana's, of this
 * interface, by all of that, so ipsec.conf's, an IKE daemon's and the
 * interfaces' own are never taken out.  The selectors put in are kept
 * with the SPIs (STATE_FILE), so that a safe job can put them back.
 */
#define	SP_MAX		16	/* selectors an interface takes */

/* A prefix (an address alone: all of it) as a sockaddr, port 0. */
static bool
sp_prefix(const char *s, struct sockaddr_storage *ss, uint8_t *plen)
{
	char		 buf[INET6_ADDRSTRLEN + 5], *slash;
	const char	*e;
	long long	 n;

	if (s == NULL || strlcpy(buf, s, sizeof(buf)) >= sizeof(buf))
		return (false);
	if ((slash = strchr(buf, '/')) != NULL)
		*slash++ = '\0';
	if (!addr_ok(buf, &(int){ 0 }))
		return (false);
	sa_sockaddr(buf, ss);
	*plen = ss->ss_family == AF_INET6 ? 128 : 32;
	if (slash != NULL) {
		n = strtonum(slash, 0, *plen, &e);
		if (e != NULL)
			return (false);
		*plen = (uint8_t)n;
	}
	return (true);
}

static void
sp_port(struct sockaddr_storage *ss, uint16_t port)
{

	if (ss->ss_family == AF_INET)
		((struct sockaddr_in *)ss)->sin_port = htons(port);
	else if (ss->ss_family == AF_INET6)
		((struct sockaddr_in6 *)ss)->sin6_port = htons(port);
}

/*
 * A selector from its words: "src prefix dst prefix [proto p] [sport n]
 * [dport n]", proto a number or any, tcp, udp, sctp, icmp, ipv6-icmp,
 * a port single (RFC 9061's, no ranges) and only with tcp, udp or sctp.
 * Without any, none given (unpolicy's: all).  NULL or what is wrong.
 */
static const char *
sp_words(const char *const *v, size_t nv, struct sp_sel *sel)
{
	static const struct { const char *name; uint8_t n; } protos[] = {
		{ "any", IPSEC_ULPROTO_ANY }, { "tcp", IPPROTO_TCP },
		{ "udp", IPPROTO_UDP }, { "sctp", IPPROTO_SCTP },
		{ "icmp", IPPROTO_ICMP }, { "ipv6-icmp", IPPROTO_ICMPV6 },
	};
	const char	*src, *dst, *e;
	long long	 sport, dport, n;
	size_t		 i, j;

	memset(sel, 0, sizeof(*sel));
	sel->proto = IPSEC_ULPROTO_ANY;
	src = dst = NULL;
	sport = dport = 0;
	for (i = 0; i < nv; i += 2) {
		if (i + 1 >= nv)
			return ("a word's value is missing");
		if (strcmp(v[i], "src") == 0)
			src = v[i + 1];
		else if (strcmp(v[i], "dst") == 0)
			dst = v[i + 1];
		else if (strcmp(v[i], "proto") == 0) {
			for (j = 0; j < nitems(protos); j++)
				if (strcmp(v[i + 1], protos[j].name) == 0)
					break;
			if (j < nitems(protos))
				sel->proto = protos[j].n;
			else {
				n = strtonum(v[i + 1], 0, 255, &e);
				if (e != NULL)
					return ("proto is a number, 0 to 255, or "
					    "any, tcp, udp, sctp, icmp, "
					    "ipv6-icmp");
				sel->proto = (uint8_t)n;
			}
		} else if (strcmp(v[i], "sport") == 0 || strcmp(v[i],
		    "dport") == 0) {
			n = strtonum(v[i + 1], 1, 65535, &e);
			if (e != NULL)
				return ("a port is one, 1 to 65535: no ranges");
			if (v[i][0] == 's')
				sport = n;
			else
				dport = n;
		} else
			return ("a policy's words are src, dst, proto, sport and "
			    "dport");
	}
	if (src == NULL && dst == NULL && nv == 0)
		return (NULL);
	if (!sp_prefix(src, &sel->src, &sel->splen) || !sp_prefix(dst,
	    &sel->dst, &sel->dplen))
		return ("src and dst are the selector's prefixes, 10.1.0.0/24 "
		    "or an address");
	if (sel->src.ss_family != sel->dst.ss_family)
		return ("src and dst are of one family");
	if ((sport != 0 || dport != 0) && sel->proto != IPPROTO_TCP &&
	    sel->proto != IPPROTO_UDP && sel->proto != IPPROTO_SCTP)
		return ("ports are tcp's, udp's or sctp's: say proto");
	sel->sport = (uint16_t)sport;
	sel->dport = (uint16_t)dport;
	sp_port(&sel->src, sel->sport);
	sp_port(&sel->dst, sel->dport);
	sel->given = true;
	return (NULL);
}

static bool
sp_port_same(const struct sockaddr_storage *a, const struct sockaddr_storage *b)
{
	const void	*va = a, *vb = b;

	if (a->ss_family == AF_INET)
		return (((const struct sockaddr_in *)va)->sin_port ==
		    ((const struct sockaddr_in *)vb)->sin_port);
	return (((const struct sockaddr_in6 *)va)->sin6_port ==
	    ((const struct sockaddr_in6 *)vb)->sin6_port);
}

/* Whether a policy the kernel has is sel's, in its direction. */
static bool
sp_is_sel(const struct pfkey_sp *k, const struct sp_sel *sel)
{
	const struct sockaddr_storage	*s, *d;
	uint8_t				 sl, dl;

	if (k->dir == IPSEC_DIR_OUTBOUND) {
		s = &sel->src;
		d = &sel->dst;
		sl = sel->splen;
		dl = sel->dplen;
	} else {
		s = &sel->dst;
		d = &sel->src;
		sl = sel->dplen;
		dl = sel->splen;
	}
	return (k->proto == sel->proto && k->splen == sl && k->dplen == dl &&
	    sa_same_addr(&k->src, s) && sa_same_addr(&k->dst, d) &&
	    sp_port_same(&k->src, s) && sp_port_same(&k->dst, d));
}

/* Whether a policy is Arcana's, of the interface of reqid between l and
 * r: everything Arcana puts in, and nothing else does. */
static bool
sp_is_ours(const struct pfkey_sp *k, uint32_t reqid,
    const struct sockaddr_storage *l, const struct sockaddr_storage *r)
{

	return (k->scope != IPSEC_POLICYSCOPE_IFNET && k->priority ==
	    PFKEY_SP_MARK && k->type == IPSEC_POLICY_IPSEC && k->nreq == 1 &&
	    k->rproto == IPPROTO_ESP && k->mode == IPSEC_MODE_TUNNEL &&
	    ((k->dir == IPSEC_DIR_OUTBOUND && k->level == IPSEC_LEVEL_UNIQUE &&
	    k->reqid == reqid && sa_same_addr(&k->tsrc, l) &&
	    sa_same_addr(&k->tdst, r)) || (k->dir == IPSEC_DIR_INBOUND &&
	    k->level == IPSEC_LEVEL_USE && sa_same_addr(&k->tsrc, r) &&
	    sa_same_addr(&k->tdst, l))));
}

/* What a dump found: the interface's own policies' reqid, and
 * Arcana's policies of it (its reqid, between its ends). */
struct sp_found {
	struct sockaddr_storage	 l, r;
	uint32_t		 reqid;
	unsigned int		 ifindex;
	uint32_t		 ifreqid;
	bool			 ifseen;
	struct pfkey_sp		 v[2 * SP_MAX + 8];
	size_t			 n;
};

static void
sp_found_one(const struct pfkey_sp *k, void *arg)
{
	struct sp_found	*f = arg;

	if (k->scope == IPSEC_POLICYSCOPE_IFNET) {
		if (f->ifindex != 0 && k->priority == f->ifindex &&
		    k->type == IPSEC_POLICY_IPSEC && k->nreq > 0 &&
		    !f->ifseen) {
			f->ifseen = true;
			f->ifreqid = k->reqid;
		}
		return;
	}
	if (sp_is_ours(k, f->reqid, &f->l, &f->r) && f->n < nitems(f->v))
		f->v[f->n++] = *k;
}

/* The SPD read: what the interface's own policies and Arcana's are.
 * -1 when it could not be. */
static int
sp_read(struct work *w, int *fdp, const struct arc_job_spec *sp,
    struct sp_found *f, const char **errp)
{
	const char	*ifname = sp->interface;
	int		 step;

	memset(f, 0, sizeof(*f));
	sa_sockaddr(sp->tunnel_local, &f->l);
	sa_sockaddr(sp->tunnel_remote, &f->r);
	f->reqid = sp->reqid;
	step = step_begin(w, STEP_SYSCALL, "PF_KEY SADB_X_SPDDUMP", "the SPD: "
	    "%s's own policies and Arcana's on its SAs", ifname);
	if (work_dry(w, step))
		return (0);
	f->ifindex = if_nametoindex(ifname);
	if (sa_fd(w, fdp, errp) == -1 || pfkey_spddump(w, *fdp, sp_found_one,
	    f, errp) == -1) {
		step_end(w, step, false, "%s", *errp);
		return (-1);
	}
	step_end(w, step, true, "%s: %s; %zu of Arcana's", ifname, f->ifseen ?
	    wfmt(w, "its own policies on reqid %u", f->ifreqid) : f->ifindex ==
	    0 ? "not here" : "no policies of its own (no tunnel yet)", f->n);
	return (0);
}

/*
 * The ipsec(4) reqid mapping: the interface's own policies take the SAs
 * of their reqid alone, so SAs or policies on another one would serve
 * nothing of it.  An interface not here, or without a tunnel yet, has
 * none to tell: the reqid as given.
 */
static int
sp_reqid_check(struct work *w, const struct arc_job_spec *sp,
    const struct sp_found *f, const char **errp)
{

	if (f->ifseen && f->ifreqid != sp->reqid) {
		*errp = wfmt(w, "%s's own policies take reqid %u, not %u: its "
		    "SAs go on that one (ifconfig %s reqid)", sp->interface,
		    f->ifreqid, sp->reqid, sp->interface);
		return (-1);
	}
	return (0);
}

/* A selector as a step says it. */
static const char *
sp_text(struct work *w, const struct sp_sel *sel)
{
	char	 a[INET6_ADDRSTRLEN], b[INET6_ADDRSTRLEN];
	const void *va = &sel->src, *vb = &sel->dst;

	if (sel->src.ss_family == AF_INET) {
		inet_ntop(AF_INET, &((const struct sockaddr_in *)va)->sin_addr,
		    a, sizeof(a));
		inet_ntop(AF_INET, &((const struct sockaddr_in *)vb)->sin_addr,
		    b, sizeof(b));
	} else {
		inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)va)->
		    sin6_addr, a, sizeof(a));
		inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)vb)->
		    sin6_addr, b, sizeof(b));
	}
	return (wfmt(w, "%s/%u%s to %s/%u%s, %s", a, sel->splen,
	    sel->sport != 0 ? wfmt(w, " port %u", sel->sport) : "", b,
	    sel->dplen, sel->dport != 0 ? wfmt(w, " port %u", sel->dport) : "",
	    sel->proto == IPSEC_ULPROTO_ANY ? "any protocol" : wfmt(w,
	    "protocol %u", sel->proto)));
}

/* Arcana's policy of id taken out; one gone already is none to take
 * out. */
static int
sp_del(struct work *w, int *fdp, const struct pfkey_sp *k, const char **errp)
{
	const char	*e;
	int		 step;

	step = step_begin(w, STEP_SYSCALL, "PF_KEY SADB_X_SPDDELETE2", "spid "
	    "%u (%s)", k->id, k->dir == IPSEC_DIR_OUTBOUND ? "out" : "in");
	if (work_dry(w, step))
		return (0);
	e = NULL;
	if (sa_fd(w, fdp, &e) == -1 || pfkey_spddelete(w, *fdp, k->id, &e) ==
	    -1) {
		if (errno == EINVAL || errno == ENOENT || errno == ESRCH) {
			step_end(w, step, true, "spid %u: none there", k->id);
			return (0);
		}
		*errp = wfmt(w, "spid %u: %s", k->id, e);
		step_end(w, step, false, "%s", *errp);
		return (-1);
	}
	step_end(w, step, true, NULL);
	return (0);
}

/* Arcana's policies of the interface taken out: those of sel, or every
 * one when sel is NULL; how many in *n. */
static int
sp_drop(struct work *w, int *fdp, const struct arc_job_spec *sp,
    const struct sp_found *f, const struct sp_sel *sel, size_t *n,
    const char **errp)
{
	struct sockaddr_storage	l, r;
	size_t			i;

	sa_sockaddr(sp->tunnel_local, &l);
	sa_sockaddr(sp->tunnel_remote, &r);
	*n = 0;
	for (i = 0; i < f->n; i++) {
		if (!sp_is_ours(&f->v[i], sp->reqid, &l, &r) || (sel != NULL &&
		    !sp_is_sel(&f->v[i], sel)))
			continue;
		if (sp_del(w, fdp, &f->v[i], errp) != 0)
			return (-1);
		(*n)++;
	}
	return (0);
}

/* One policy put in, sel's in dir, on the interface's SAs; its id. */
static int
sp_put1(struct work *w, int *fdp, const struct arc_job_spec *sp,
    const struct sp_sel *sel, uint8_t dir, uint32_t *id, const char **errp)
{
	struct pfkey_sp	 k;
	const char	*l, *r, *what;
	int		 step;

	l = dir == IPSEC_DIR_OUTBOUND ? sp->tunnel_local : sp->tunnel_remote;
	r = dir == IPSEC_DIR_OUTBOUND ? sp->tunnel_remote : sp->tunnel_local;
	memset(&k, 0, sizeof(k));
	k.src = dir == IPSEC_DIR_OUTBOUND ? sel->src : sel->dst;
	k.dst = dir == IPSEC_DIR_OUTBOUND ? sel->dst : sel->src;
	k.splen = dir == IPSEC_DIR_OUTBOUND ? sel->splen : sel->dplen;
	k.dplen = dir == IPSEC_DIR_OUTBOUND ? sel->dplen : sel->splen;
	k.proto = sel->proto;
	k.dir = dir;
	k.type = IPSEC_POLICY_IPSEC;
	k.priority = PFKEY_SP_MARK;
	k.rproto = IPPROTO_ESP;
	k.mode = IPSEC_MODE_TUNNEL;
	/* use, reqid 0, as ipsec_set_policy() has a level but unique. */
	k.level = dir == IPSEC_DIR_OUTBOUND ? IPSEC_LEVEL_UNIQUE :
	    IPSEC_LEVEL_USE;
	k.reqid = dir == IPSEC_DIR_OUTBOUND ? (uint16_t)sp->reqid : 0;
	sa_sockaddr(l, &k.tsrc);
	sa_sockaddr(r, &k.tdst);
	what = wfmt(w, "%s %s, ESP in tunnel mode %s to %s, %s", dir ==
	    IPSEC_DIR_OUTBOUND ? "out" : "in", dir == IPSEC_DIR_OUTBOUND ?
	    sp_text(w, sel) : wfmt(w, "the other way of %s", sp_text(w, sel)),
	    l, r, dir == IPSEC_DIR_OUTBOUND ? wfmt(w, "unique:%u", sp->reqid) :
	    "use");
	step = step_begin(w, STEP_SYSCALL, "PF_KEY SADB_X_SPDADD", "%s", what);
	*id = 0;
	if (work_dry(w, step))
		return (0);
	if (sa_fd(w, fdp, errp) == -1 || pfkey_spdadd(w, *fdp, &k, errp) ==
	    -1) {
		if (errno == EEXIST)
			*errp = wfmt(w, "%s: a policy of that selector and "
			    "direction is there already, not Arcana's (ipsec.conf, "
			    "an IKE daemon): left as it is", sp_text(w, sel));
		step_end(w, step, false, "%s", *errp);
		return (-1);
	}
	*id = k.id;
	step_end(w, step, true, "%s: spid %u", what, k.id);
	return (0);
}

/* The selectors kept: the state's "policies", each its words. */
static ucl_object_t *
sp_kept(const struct sp_sel *sel)
{
	ucl_object_t	*o;
	char		 a[INET6_ADDRSTRLEN], b[INET6_ADDRSTRLEN];
	const void	*va = &sel->src, *vb = &sel->dst;
	char		 buf[INET6_ADDRSTRLEN + 5];

	if (sel->src.ss_family == AF_INET) {
		inet_ntop(AF_INET, &((const struct sockaddr_in *)va)->sin_addr,
		    a, sizeof(a));
		inet_ntop(AF_INET, &((const struct sockaddr_in *)vb)->sin_addr,
		    b, sizeof(b));
	} else {
		inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)va)->
		    sin6_addr, a, sizeof(a));
		inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)vb)->
		    sin6_addr, b, sizeof(b));
	}
	o = ucl_object_typed_new(UCL_OBJECT);
	snprintf(buf, sizeof(buf), "%s/%u", a, sel->splen);
	ucl_object_insert_key(o, ucl_object_fromstring(buf), "src", 0, true);
	snprintf(buf, sizeof(buf), "%s/%u", b, sel->dplen);
	ucl_object_insert_key(o, ucl_object_fromstring(buf), "dst", 0, true);
	ucl_object_insert_key(o, ucl_object_fromint(sel->proto), "proto", 0,
	    false);
	if (sel->sport != 0)
		ucl_object_insert_key(o, ucl_object_fromint(sel->sport), "sport",
		    0, false);
	if (sel->dport != 0)
		ucl_object_insert_key(o, ucl_object_fromint(sel->dport), "dport",
		    0, false);
	return (o);
}

/* A kept selector read again; false when it is not whole. */
static bool
sp_unkept(struct work *w, const ucl_object_t *o, struct sp_sel *sel)
{
	const char	*v[10];
	size_t		 n;

	n = 0;
	v[n++] = "src";
	v[n++] = sstr(o, "src");
	v[n++] = "dst";
	v[n++] = sstr(o, "dst");
	v[n++] = "proto";
	v[n++] = wfmt(w, "%u", u32(o, "proto"));
	if (u32(o, "sport") != 0) {
		v[n++] = "sport";
		v[n++] = wfmt(w, "%u", u32(o, "sport"));
	}
	if (u32(o, "dport") != 0) {
		v[n++] = "dport";
		v[n++] = wfmt(w, "%u", u32(o, "dport"));
	}
	return (v[1] != NULL && v[3] != NULL && sp_words(v, n, sel) == NULL &&
	    sel->given);
}

/* The kept selectors without sel's (or without any, sel NULL). */
static void
sp_forget(struct work *w, ucl_object_t *stt, const struct sp_sel *sel)
{
	const ucl_object_t	*o;
	ucl_object_t		*arr;
	ucl_object_iter_t	 it;
	struct sp_sel		 k;

	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while (sel != NULL && (o = ucl_object_iterate(ucl_object_lookup(stt,
	    "policies"), &it, true)) != NULL)
		if (!sp_unkept(w, o, &k) || k.proto != sel->proto || k.splen !=
		    sel->splen || k.dplen != sel->dplen || !sa_same_addr(&k.src,
		    &sel->src) || !sa_same_addr(&k.dst, &sel->dst) || k.sport !=
		    sel->sport || k.dport != sel->dport)
			ucl_array_append(arr, ucl_object_copy(o));
	if (ucl_array_size(arr) == 0) {
		ucl_object_unref(arr);
		(void)ucl_object_delete_key(stt, "policies");
	} else
		ucl_object_replace_key(stt, arr, "policies", 0, false);
}

/*
 * A selector's two policies put in, out and in, its old ones (Arcana's)
 * taken out first so a job can run again; read back by a dump, each by
 * its id: global, the priority, the selector, ESP in tunnel mode
 * between the ends, out unique on the reqid, in use.  An in refused
 * takes the out with it: never half a pair.
 */
static int
sp_put(struct work *w, int *fdp, const struct arc_job_spec *sp,
    const struct sp_sel *sel, const char **errp)
{
	struct sockaddr_storage	 l, r;
	struct sp_found		 f;
	struct pfkey_sp		 gone;
	uint32_t		 out, in;
	const char		*bad;
	size_t			 i, n;
	int			 step, seen;

	if (sp_read(w, fdp, sp, &f, errp) != 0 ||
	    sp_reqid_check(w, sp, &f, errp) != 0 ||
	    sp_drop(w, fdp, sp, &f, sel, &n, errp) != 0)
		return (-1);
	if (sp_put1(w, fdp, sp, sel, IPSEC_DIR_OUTBOUND, &out, errp) != 0)
		return (-1);
	if (sp_put1(w, fdp, sp, sel, IPSEC_DIR_INBOUND, &in, errp) != 0) {
		memset(&gone, 0, sizeof(gone));
		gone.id = out;
		gone.dir = IPSEC_DIR_OUTBOUND;
		(void)sp_del(w, fdp, &gone, &bad);
		return (-1);
	}
	step = step_begin(w, STEP_SYSCALL, "PF_KEY SADB_X_SPDDUMP", "spid %u "
	    "and %u read back", out, in);
	if (work_dry(w, step))
		return (0);
	f.ifindex = 0;
	f.ifseen = false;
	f.n = 0;
	if (pfkey_spddump(w, *fdp, sp_found_one, &f, errp) == -1) {
		step_end(w, step, false, "%s", *errp);
		return (-1);
	}
	sa_sockaddr(sp->tunnel_local, &l);
	sa_sockaddr(sp->tunnel_remote, &r);
	seen = 0;
	bad = NULL;
	for (i = 0; i < f.n; i++) {
		if (f.v[i].id != out && f.v[i].id != in)
			continue;
		seen++;
		if (f.v[i].dir != (f.v[i].id == out ? IPSEC_DIR_OUTBOUND :
		    IPSEC_DIR_INBOUND))
			bad = "another direction";
		else if (!sp_is_sel(&f.v[i], sel))
			bad = "another selector";
		else if (!sp_is_ours(&f.v[i], sp->reqid, &l, &r))
			bad = "another request";
	}
	if (seen != 2 || bad != NULL) {
		*errp = wfmt(w, "%s: the kernel has its policies %s", sp_text(w,
		    sel), bad != NULL ? wfmt(w, "with %s", bad) : "not");
		step_end(w, step, false, "%s", *errp);
		return (-1);
	}
	step_end(w, step, true, "spid %u out, %u in: global, priority %#x, "
	    "ESP in tunnel mode %s to %s, out unique:%u, in use", out, in,
	    PFKEY_SP_MARK, sp->tunnel_local, sp->tunnel_remote, sp->reqid);
	return (0);
}

/* policy, unpolicy: a selector's policies put in or taken out, the
 * selectors kept with the SPIs. */
static int
sp_job(struct work *w, const struct arc_job_spec *sp, int *fdp,
    ucl_object_t *stt, const char **errp)
{
	struct sp_sel	 sel;
	struct sp_found	 f;
	size_t		 n;
	int		 step;

	(void)sp_words(sp->names.v, sp->names.n, &sel);
	if (strcmp(sp->verb, "policy") == 0) {
		sp_forget(w, stt, &sel);
		if (ucl_array_size(ucl_object_lookup(stt, "policies")) >=
		    SP_MAX) {
			*errp = wfmt(w, "%s takes %d selectors at most",
			    sp->interface, SP_MAX);
			return (-1);
		}
		if (sp_put(w, fdp, sp, &sel, errp) != 0)
			return (-1);
		if (ucl_object_lookup(stt, "policies") == NULL)
			ucl_object_insert_key(stt, ucl_object_typed_new(
			    UCL_ARRAY), "policies", 0, false);
		ucl_array_append((ucl_object_t *)(uintptr_t)ucl_object_lookup(
		    stt, "policies"), sp_kept(&sel));
		return (sa_state_save(w, sp->interface, stt, errp));
	}
	if (sp_read(w, fdp, sp, &f, errp) != 0)
		return (-1);
	step = step_begin(w, STEP_DAEMON, "arcana-agent", "%s: %s", sp->interface,
	    sel.given ? wfmt(w, "the policies of %s", sp_text(w, &sel)) :
	    "Arcana's policies on its SAs");
	if (sp_drop(w, fdp, sp, &f, sel.given ? &sel : NULL, &n, errp) != 0) {
		step_end(w, step, false, "%s", *errp);
		return (-1);
	}
	step_end(w, step, true, "%zu taken out", n);
	sp_forget(w, stt, sel.given ? &sel : NULL);
	return (sa_state_save(w, sp->interface, stt, errp));
}

/* After a safe job's files are back: Arcana's policies of the interface
 * as the state kept them. */
static int
sp_resync(struct work *w, const struct arc_job_spec *sp, const char **errp)
{
	const ucl_object_t	*o;
	ucl_object_t		*stt;
	ucl_object_iter_t	 it;
	struct sp_found		 f;
	struct sp_sel		 sel;
	size_t			 n;
	int			 fd, rc;

	fd = -1;
	rc = sp_read(w, &fd, sp, &f, errp) != 0 || sp_drop(w, &fd,
	    sp, &f, NULL, &n, errp) != 0 ? -1 : 0;
	stt = rc == 0 ? sa_state_load(w, sp->interface) : NULL;
	it = NULL;
	while (rc == 0 && stt != NULL && (o = ucl_object_iterate(
	    ucl_object_lookup(stt, "policies"), &it, true)) != NULL)
		if (sp_unkept(w, o, &sel))
			rc = sp_put(w, &fd, sp, &sel, errp);
	if (stt != NULL)
		ucl_object_unref(stt);
	if (fd != -1)
		close(fd);
	return (rc);
}

/*
 * The SAs set, derived, turned or cleared.  set and derive put both
 * directions in (the old ones kept here taken out first, so a step
 * can be run again); derive with next, from the next pair, puts in
 * the directions install says and keeps the SPIs as the next ones, the
 * old outbound SA taken out with the new one in (the kernel keeps
 * sending on the old one otherwise, net.key.preferred_oldsa); commit
 * takes the old inbound SA out, makes the next pair the pair, and the
 * next SPIs the SPIs: a rotation in three steps on each end, in, out,
 * commit, so neither end sends on keys the other has not got, nor
 * drops what the other still sends (R110, R112).
 */
static int
sa_job1(struct work *w, const struct arc_job_spec *sp, int *fdp,
    const char **errp)
{
	struct sa_words	 sw;
	ucl_object_t	*stt;
	const char	*e, *l, *r;
	char		 pub[PUB_B64 + 1], kout[80], kin[80], aout[136], ain[136];
	unsigned char	 okm[2 * (36 + 64) + 8];
	size_t		 enclen, authlen, at;
	int		 step, rc;
	bool		 clear, derive, commit, rotate, lower, in, out;

	if ((e = sa_check(sp)) != NULL) {
		*errp = e;
		return (-1);
	}
	if (strcmp(sp->verb, "key") == 0) {
		rotate = word_next(sp);
		step = step_begin(w, STEP_DAEMON, "arcana-agent", "%s: "
		    "its %skey pair", sp->interface, rotate ? "next " : "");
		if (key_make(w, sp->interface, rotate, pub, sizeof(pub), errp) !=
		    0) {
			step_end(w, step, false, "%s", *errp);
			return (-1);
		}
		step_end(w, step, true, "public %s", pub);
		return (0);
	}
	clear = strcmp(sp->verb, "clear") == 0;
	commit = strcmp(sp->verb, "commit") == 0;
	derive = strcmp(sp->verb, "derive") == 0;
	l = sp->tunnel_local;
	r = sp->tunnel_remote;
	memset(&sw, 0, sizeof(sw));
	kout[0] = kin[0] = aout[0] = ain[0] = '\0';
	if (!clear && !commit)
		(void)sa_parse(sp, &sw, derive);
	if ((stt = sa_state_load(w, sp->interface)) == NULL)
		stt = ucl_object_typed_new(UCL_OBJECT);
	rotate = derive && sw.next;
	in = sw.install != 2;
	out = sw.install != 1;
	if (strcmp(sp->verb, "policy") == 0 || strcmp(sp->verb, "unpolicy") ==
	    0) {
		rc = sp_job(w, sp, fdp, stt, errp);
		ucl_object_unref(stt);
		return (rc);
	}
	if (clear) {
		struct sp_found	f;
		size_t		n;

		/* The SAs, then Arcana's policies on them: what was sent
		 * through them dropped meanwhile, never sent plain. */
		(void)sa_clear(w, fdp, l, r);
		if (sp_read(w, fdp, sp, &f, &e) == 0)
			(void)sp_drop(w, fdp, sp, &f, NULL, &n, &e);
		(void)unlink(key_path(w, sp->interface, true));
		(void)sa_state_save(w, sp->interface, NULL, errp);
		ucl_object_unref(stt);
		return (0);
	}
	if (commit) {
		if (ucl_object_lookup(stt, "next_spi_in") == NULL ||
		    ucl_object_lookup(stt, "next_spi_out") == NULL) {
			*errp = wfmt(w, "%s: nothing to commit: derive with next, "
			    "install in and out, first", sp->interface);
			ucl_object_unref(stt);
			return (-1);
		}
		if (access(key_path(w, sp->interface, true), F_OK) != 0) {
			*errp = wfmt(w, "%s has no next pair to commit",
			    sp->interface);
			ucl_object_unref(stt);
			return (-1);
		}
		step = step_begin(w, STEP_DAEMON, "arcana-agent", "%s: "
		    "the next keys the keys", sp->interface);
		/* The old inbound SA out (the outbound went with the new one
		 * in), the next pair the pair. */
		sa_del(w, fdp, r, l, u32(stt, "spi_in"));
		if (rename(key_path(w, sp->interface, true), key_path(w,
		    sp->interface, false)) != 0) {
			*errp = wfmt(w, "%s: the next pair not made the pair: %s",
			    sp->interface, strerror(errno));
			step_end(w, step, false, "%s", *errp);
			ucl_object_unref(stt);
			return (-1);
		}
		ucl_object_replace_key(stt, ucl_object_fromint(u32(stt,
		    "next_spi_in")), "spi_in", 0, false);
		ucl_object_replace_key(stt, ucl_object_fromint(u32(stt,
		    "next_spi_out")), "spi_out", 0, false);
		ucl_object_replace_key(stt, ucl_object_fromint((int64_t)time(NULL)),
		    "at", 0, false);
		(void)ucl_object_delete_key(stt, "next_spi_in");
		(void)ucl_object_delete_key(stt, "next_spi_out");
		if (ucl_object_lookup(stt, "next_derive") != NULL)
			ucl_object_replace_key(stt, ucl_object_copy(ucl_object_lookup(
			    stt, "next_derive")), "derive", 0, false);
		else
			(void)ucl_object_delete_key(stt, "derive");
		(void)ucl_object_delete_key(stt, "next_derive");
		rc = sa_state_save(w, sp->interface, stt, errp);
		if (rc == 0)
			step_end(w, step, true, "spi in %#x out %#x", u32(stt,
			    "spi_in"), u32(stt, "spi_out"));
		else
			step_end(w, step, false, "%s", *errp);
		ucl_object_unref(stt);
		/* The next pair the pair: its half is another. */
		key_told(w, sp->interface);
		return (rc);
	}
	/* The interface's own policies' reqid, before anything changes. */
	{
		struct sp_found	f;

		if (sp_read(w, fdp, sp, &f, errp) != 0 || sp_reqid_check(w, sp,
		    &f, errp) != 0) {
			ucl_object_unref(stt);
			return (-1);
		}
	}
	if (derive) {
		/* 256-bit AES, or GCM with its nonce; the HMAC of its size. */
		enclen = strcmp(sw.enc, "aes-gcm-16") == 0 ? 36 : 32;
		authlen = sw.auth == NULL ? 0 : strcmp(sw.auth, "hmac-sha1") == 0
		    ? 20 : strcmp(sw.auth, "hmac-sha2-256") == 0 ? 32 : 64;
		if (key_derive(w, sp->interface, sw.peer, HKDF_SALT, sw.epoch,
		    sw.next, okm,
		    2 * (enclen + authlen) + 8, &lower, errp) != 0) {
			ucl_object_unref(stt);
			return (-1);
		}
		/* A to B first: out for A, in for B. */
		at = 0;
		hex_of(okm + at, enclen, lower ? kout : kin);
		at += enclen;
		if (authlen > 0)
			hex_of(okm + at, authlen, lower ? aout : ain);
		at += authlen;
		hex_of(okm + at, enclen, lower ? kin : kout);
		at += enclen;
		if (authlen > 0)
			hex_of(okm + at, authlen, lower ? ain : aout);
		at += authlen;
		sw.spi_out = spi_of(okm + at + (lower ? 0 : 4));
		sw.spi_in = spi_of(okm + at + (lower ? 4 : 0));
		if (sw.spi_in == sw.spi_out)
			sw.spi_in ^= 1;
		sw.key_out = kout;
		sw.key_in = kin;
		sw.akey_out = authlen > 0 ? aout : NULL;
		sw.akey_in = authlen > 0 ? ain : NULL;
		OPENSSL_cleanse(okm, sizeof(okm));
	}
	/* What is being put in, taken out first where it is in already. */
	if (rotate) {
		if (in)
			sa_del(w, fdp, r, l, u32(stt, "next_spi_in"));
		if (out)
			sa_del(w, fdp, l, r, u32(stt, "next_spi_out"));
	} else {
		sa_del(w, fdp, r, l, u32(stt, "spi_in"));
		sa_del(w, fdp, l, r, u32(stt, "spi_out"));
	}
	/* Out, then in. */
	rc = 0;
	if (out)
		rc = sa_put(w, fdp, &sw, sp->reqid, l, r, sw.spi_out, sw.key_out,
		    sw.akey_out, errp);
	if (rc == 0 && in)
		rc = sa_put(w, fdp, &sw, sp->reqid, r, l, sw.spi_in, sw.key_in,
		    sw.akey_in, errp);
	/* A rotation's new outbound SA in: the old one out at once, so this
	 * end sends on the new keys from here on, whatever the kernel
	 * prefers; the far end has the new inbound one already. */
	if (rc == 0 && rotate && out && u32(stt, "spi_out") != 0 && u32(stt,
	    "spi_out") != sw.spi_out)
		sa_del(w, fdp, l, r, u32(stt, "spi_out"));
	OPENSSL_cleanse(kout, sizeof(kout));
	OPENSSL_cleanse(kin, sizeof(kin));
	OPENSSL_cleanse(aout, sizeof(aout));
	OPENSSL_cleanse(ain, sizeof(ain));
	if (rc != 0) {
		ucl_object_unref(stt);
		return (-1);
	}
	/* Kept: the SPIs put in, for a rotation to take out; when; for how
	 * long; and a derive's words, so that a safe job not confirmed can
	 * put the SAs in again as they were (set by hand, they cannot be). */
	if (derive) {
		ucl_object_t	*d = derive_words(&sw);

		/* A rotation derives in, then out: both, once both are. */
		if (rotate && sw.install != 0 && ucl_object_lookup(stt,
		    "next_derive") != NULL && sstr(ucl_object_lookup(stt,
		    "next_derive"), "install") != NULL && strcmp(sstr(
		    ucl_object_lookup(stt, "next_derive"), "install"), sstr(d,
		    "install")) != 0)
			ucl_object_replace_key(d, ucl_object_fromstring("both"),
			    "install", 0, false);
		ucl_object_replace_key(stt, d, rotate ? "next_derive" : "derive",
		    0, false);
	} else
		(void)ucl_object_delete_key(stt, "derive");
	if (in)
		ucl_object_replace_key(stt, ucl_object_fromint(sw.spi_in), rotate ?
		    "next_spi_in" : "spi_in", 0, false);
	if (out)
		ucl_object_replace_key(stt, ucl_object_fromint(sw.spi_out), rotate ?
		    "next_spi_out" : "spi_out", 0, false);
	if (!rotate)
		ucl_object_replace_key(stt, ucl_object_fromint((int64_t)time(NULL)),
		    "at", 0, false);
	if (sw.lifetime != 0)
		ucl_object_replace_key(stt, ucl_object_fromint(sw.lifetime),
		    "lifetime", 0, false);
	rc = sa_state_save(w, sp->interface, stt, errp);
	ucl_object_unref(stt);
	return (rc);
}

static int
sa_job(struct work *w, const struct arc_job_spec *sp, const char **errp)
{
	int	fd, rc;

	fd = -1;
	rc = sa_job1(w, sp, &fd, errp);
	if (fd != -1)
		close(fd);
	return (rc);
}

/* ---- Safe mode ------------------------------------------------------ */

static const char *
sstr(const ucl_object_t *o, const char *key)
{
	const ucl_object_t	*v;

	v = o != NULL ? ucl_object_lookup(o, key) : NULL;
	return (v != NULL && ucl_object_type(v) == UCL_STRING ?
	    ucl_object_tostring(v) : NULL);
}

/* A derive's words as the state file keeps them: nothing secret, the
 * keys come from the pair and the peer's public half. */
static ucl_object_t *
derive_words(const struct sa_words *sw)
{
	ucl_object_t	*o;

	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, ucl_object_fromstring(sw->peer), "peer", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromint(sw->epoch), "epoch", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromstring(sw->enc), "enc", 0,
	    false);
	if (sw->auth != NULL)
		ucl_object_insert_key(o, ucl_object_fromstring(sw->auth), "auth",
		    0, false);
	ucl_object_insert_key(o, ucl_object_fromstring(sw->install == 1 ? "in" :
	    sw->install == 2 ? "out" : "both"), "install", 0, false);
	if (sw->encap)
		ucl_object_insert_key(o, ucl_object_frombool(true), "encap", 0,
		    false);
	if (sw->esn)
		ucl_object_insert_key(o, ucl_object_frombool(true), "esn", 0,
		    false);
	if (sw->lifetime != 0)
		ucl_object_insert_key(o, ucl_object_fromint(sw->lifetime),
		    "lifetime", 0, false);
	return (o);
}

/* The SAs derived again from the words kept, the pair's or the next's. */
static int
sa_rederive(struct work *w, const struct arc_job_spec *sp,
    const ucl_object_t *d, bool next, const char **errp)
{
	struct arc_job_spec	 s;
	const char		*v[20];
	size_t			 n;

	if (sstr(d, "peer") == NULL || sstr(d, "enc") == NULL) {
		*errp = wfmt(w, "%s: the words of its SAs were not kept whole",
		    sp->interface);
		return (-1);
	}
	n = 0;
	v[n++] = "peer";
	v[n++] = sstr(d, "peer");
	v[n++] = "epoch";
	v[n++] = wfmt(w, "%u", u32(d, "epoch"));
	v[n++] = "enc";
	v[n++] = sstr(d, "enc");
	if (sstr(d, "auth") != NULL) {
		v[n++] = "auth";
		v[n++] = sstr(d, "auth");
	}
	v[n++] = "install";
	v[n++] = sstr(d, "install") != NULL ? sstr(d, "install") : "both";
	if (ucl_object_toboolean(ucl_object_lookup(d, "encap")))
		v[n++] = "encap";
	if (ucl_object_toboolean(ucl_object_lookup(d, "esn")))
		v[n++] = "esn";
	if (u32(d, "lifetime") != 0) {
		v[n++] = "lifetime";
		v[n++] = wfmt(w, "%u", u32(d, "lifetime"));
	}
	if (next)
		v[n++] = "next";
	s = *sp;
	s.verb = "derive";
	s.names.n = n;
	s.names.v = v;
	return (sa_job(w, &s, errp));
}

/* The files a safe job puts back: the pair, the next pair, the state. */
void
sa_files(struct work *w, const char *ifname, const char **key,
    const char **next, const char **state)
{
	char	buf[MAXPATHLEN];

	*key = key_path(w, ifname, false);
	*next = key_path(w, ifname, true);
	sdwan_conf_path(wfmt(w, STATE_FILE, sa_ifkey(w, ifname)), buf,
	    sizeof(buf));
	*state = wstrdup(w, buf);
}

/*
 * Can a safe job of this spec be undone?  A key pair made is put back
 * from its file; the SAs in place come back only when they were
 * derived, their words kept: set by hand, their keys are nowhere.
 * NULL, or why not.
 */
const char *
sa_undo_check(struct work *w, const struct arc_job_spec *sp)
{
	ucl_object_t	*stt;
	const char	*e;

	if (sp->verb == NULL || sp->interface == NULL || strcmp(sp->verb,
	    "key") == 0 || strcmp(sp->verb, "policy") == 0 || strcmp(sp->verb,
	    "unpolicy") == 0)
		return (NULL);
	if ((stt = sa_state_load(w, sp->interface)) == NULL)
		return (NULL);
	e = NULL;
	if (((u32(stt, "spi_in") != 0 || u32(stt, "spi_out") != 0) &&
	    ucl_object_lookup(stt, "derive") == NULL) || ((u32(stt,
	    "next_spi_in") != 0 || u32(stt, "next_spi_out") != 0) &&
	    ucl_object_lookup(stt, "next_derive") == NULL))
		e = wfmt(w, "%s: the SAs in place were set by hand, not "
		    "derived, and could not be put back: not in safe mode",
		    sp->interface);
	ucl_object_unref(stt);
	return (e);
}

/*
 * After the files are back as they were: the kernel's SAs of the pair
 * gone, and those the state file says were in derived again, the
 * pair's and the next pair's.
 */
int
sa_undo(struct work *w, const struct arc_job_spec *sp, const char **errp)
{
	ucl_object_t	*stt;
	int		 step, rc, fd;
	bool		 any;

	/* A pair made undone: the one before put back, if there was one. */
	if (strcmp(sp->verb, "key") == 0) {
		if (!word_next(sp))
			key_told(w, sp->interface);
		return (0);
	}
	/* A turn undone: the pair before it put back, told. */
	if (strcmp(sp->verb, "commit") == 0)
		key_told(w, sp->interface);
	/* A selector's policies: only they, as kept. */
	if (strcmp(sp->verb, "policy") == 0 || strcmp(sp->verb, "unpolicy") ==
	    0) {
		step = step_begin(w, STEP_DAEMON, "arcana-agent", "%s: Arcana's "
		    "policies on its SAs as they were", sp->interface);
		if ((rc = sp_resync(w, sp, errp)) != 0)
			step_end(w, step, false, "%s", *errp);
		else
			step_end(w, step, true, NULL);
		return (rc);
	}
	step = step_begin(w, STEP_DAEMON, "arcana-agent", "%s: its "
	    "SAs as they were", sp->interface);
	fd = -1;
	(void)sa_clear(w, &fd, sp->tunnel_local, sp->tunnel_remote);
	if (fd != -1)
		close(fd);
	rc = 0;
	any = false;
	if ((stt = sa_state_load(w, sp->interface)) != NULL) {
		if ((u32(stt, "spi_in") != 0 || u32(stt, "spi_out") != 0) &&
		    ucl_object_lookup(stt, "derive") != NULL) {
			rc = sa_rederive(w, sp, ucl_object_lookup(stt, "derive"),
			    false, errp);
			any = true;
		}
		if (rc == 0 && (u32(stt, "next_spi_in") != 0 || u32(stt,
		    "next_spi_out") != 0) && ucl_object_lookup(stt,
		    "next_derive") != NULL) {
			rc = sa_rederive(w, sp, ucl_object_lookup(stt,
			    "next_derive"), true, errp);
			any = true;
		}
		ucl_object_unref(stt);
	}
	/* A clear took Arcana's policies on them too. */
	if (rc == 0 && strcmp(sp->verb, "clear") == 0)
		rc = sp_resync(w, sp, errp);
	if (rc != 0)
		step_end(w, step, false, "%s", *errp);
	else
		step_end(w, step, true, any ? "derived again as kept" : "none "
		    "were in: none put in");
	return (rc);
}

/*
 * The key-rotation faults held to the interfaces that have keys (their
 * pairs beside the kept files, sa_keys_json()'s): one of an interface
 * whose keys are gone cleared; with at_start, one of an interface no
 * longer turning its keys (no next SPI kept) too, its cause gone with
 * the agent before.  Between, a failed rotation's stays until one is
 * done.
 */
static void
sa_reconcile(struct work *w, bool at_start)
{
	struct fault_live	*v;
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	ucl_object_t		*top;
	size_t			 n;

	top = ucl_object_typed_new(UCL_OBJECT);
	sa_keys_json(w, top);
	n = ucl_array_size(ucl_object_lookup(top, "keys"));
	if ((v = calloc(n + 1, sizeof(*v))) == NULL) {
		ucl_object_unref(top);
		return;
	}
	n = 0;
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(top, "keys"), &it,
	    true)) != NULL) {
		if (sstr(e, "interface") == NULL)
			continue;
		v[n].object = sstr(e, "interface");
		v[n].well = at_start && !ucl_object_toboolean(ucl_object_lookup(e,
		    "pending"));
		if (v[n].well)
			v[n].reason = "its keys turn no more: none pending";
		n++;
	}
	(void)fault_reconcile("arcana-agent", "key-rotation", NULL, v, n,
	    "its manual IPsec keys are gone");
	free(v);
	ucl_object_unref(top);
}

/* At the start: the rotations' faults held to the keys there are. */
void
sa_faults_start(void)
{
	struct work	w;

	work_init(&w);
	sa_reconcile(&w, true);
	work_free(&w);
}

/* A rotation that fails is a fault on the interface, until one is done;
 * the faults held to the keys there are after every job. */
int
do_sa_job(struct work *w, const struct arc_job_spec *sp, const char **errp)
{
	const char	*ifk;
	int		 rc;
	bool		 rotation;

	rc = sa_job(w, sp, errp);
	rotation = sp->verb != NULL && sp->interface != NULL && (strcmp(sp->verb,
	    "commit") == 0 || (strcmp(sp->verb, "derive") == 0 && word_next(sp)));
	ifk = sp->interface != NULL ? sa_ifkey(w, sp->interface) : NULL;
	if (rotation && rc != 0)
		fault_set("key-rotation", "Major", ifk, "arcana-agent",
		    "the keys of %s were not turned: %s", ifk, *errp);
	else if (rotation && strcmp(sp->verb, "commit") == 0)
		fault_clear("key-rotation", ifk, "the keys of %s turned", ifk);
	if (!w->dry)
		sa_reconcile(w, false);
	return (rc);
}
