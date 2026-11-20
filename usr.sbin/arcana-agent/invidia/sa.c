/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The SD-WAN tunnels' key pairs and what is derived from them (Mplify
 * 119 §10, R51-R54): the pairs RFC 9061's lists name (arcana-ikeless'
 * key-pairs, ikeless.c), the SAs' SPIs and keys derived for its derived
 * sad-entries, a plain tunnel's STAMP key (tunnel_key_derive()), the
 * public halves told in the sdwan read and as sdwan-key events, and the
 * key-rotation faults.
 *
 * A pair is named as its interface is, a vnet jail's "<interface>@<jail>"
 * (sa_ifkey()), and kept on the host beside the agent's files whatever
 * network its SAs are of.
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
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
 * anything but this; the public half, 32 bytes, told in the sdwan read
 * (as base64) and in the lists' operational key-pairs for the console
 * to pass to the far end.  The SA keys and SPIs of both directions come
 * from the agreement with the far public half by HKDF-SHA256 (NIST SP
 * 800-56A, R54), the same on both ends: the end whose public half sorts
 * lower is A, the other B, and the material is laid out A to B first.
 * A plain tunnel's end (gre, gif, geneve) has a pair too: its STAMP key
 * is derived from it the same way, salted apart (gula/probe_stamp.c).
 * A pair turned (a new generation, R110) keeps the one before as
 * PREV_FILE, so that a commit not confirmed puts it back.
 */
#define	KEY_FILE	"sdwan-key-%s.pem"
#define	PREV_FILE	"sdwan-key-%s-prev.pem"	/* the pair before a turn */
#define	STATE_FILE	"sdwan-sa-%s.json"	/* generations, the SPIs, when */
#define	HKDF_SALT	"arcana uswe v1"
#define	PUB_B64		44	/* 32 bytes as base64 */

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

static void
pair_path(const char *fmt, const char *name, char *buf, size_t len)
{
	char	file[MAXPATHLEN];

	snprintf(file, sizeof(file), fmt, name);
	sdwan_conf_path(file, buf, len);
}

/* A pair read; NULL and why when there is none. */
static EVP_PKEY *
pair_load(const char *fmt, const char *name, char *err, size_t errlen)
{
	EVP_PKEY	*k;
	FILE		*fp;
	char		 path[MAXPATHLEN];

	pair_path(fmt, name, path, sizeof(path));
	if ((fp = fopen(path, "r")) == NULL) {
		snprintf(err, errlen, "%s has no key pair yet: its key-pair "
		    "entry first", name);
		return (NULL);
	}
	k = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);
	if (k == NULL)
		snprintf(err, errlen, "%s: the key file is not a private key",
		    name);
	return (k);
}

/* The public half of a pair; false if not X25519. */
static bool
pair_raw(EVP_PKEY *k, unsigned char raw[SA_PUB_LEN])
{
	size_t	n = SA_PUB_LEN;

	return (EVP_PKEY_get_raw_public_key(k, raw, &n) == 1 && n ==
	    SA_PUB_LEN);
}

static bool
pair_b64(EVP_PKEY *k, char *b64, size_t len)
{
	unsigned char	raw[SA_PUB_LEN];

	if (len < PUB_B64 + 1 || !pair_raw(k, raw))
		return (false);
	EVP_EncodeBlock((unsigned char *)b64, raw, SA_PUB_LEN);
	return (true);
}

/* The public half of name's pair into pub; false when it has none. */
bool
sa_pair_public(const char *name, unsigned char pub[SA_PUB_LEN])
{
	EVP_PKEY	*k;
	char		 e[160];
	bool		 ok;

	if ((k = pair_load(KEY_FILE, name, e, sizeof(e))) == NULL)
		return (false);
	ok = pair_raw(k, pub);
	EVP_PKEY_free(k);
	return (ok);
}

/*
 * A pair not what it was (made, turned, put back): told as sdwan-key
 * with its public half, so that the console gives the far end the half
 * its keys are derived from (a plain tunnel's STAMP key, the far end's
 * own derived anew only from it).
 */
static void
pair_told(const char *name)
{
	EVP_PKEY	*k;
	char		 pub[PUB_B64 + 1], qi[6 * (32 + MAXHOSTNAMELEN) + 1],
			 e[160];

	if ((k = pair_load(KEY_FILE, name, e, sizeof(e))) == NULL)
		return;
	if (pair_b64(k, pub, sizeof(pub)))
		event_add("sdwan-key", "{\"interface\":\"%s\",\"public\":"
		    "\"%s\"}", json_quote(name, qi, sizeof(qi)), pub);
	EVP_PKEY_free(k);
}

/* A new pair written to KEY_FILE of name, none there; -1 and why. */
static int
pair_make(const char *name, char *err, size_t errlen)
{
	EVP_PKEY	*k;
	FILE		*fp;
	char		 path[MAXPATHLEN];
	int		 fd;

	pair_path(KEY_FILE, name, path, sizeof(path));
	if ((k = EVP_PKEY_Q_keygen(NULL, NULL, "X25519")) == NULL) {
		snprintf(err, errlen, "OpenSSL made no X25519 key");
		return (-1);
	}
	if ((fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600)) ==
	    -1 || (fp = fdopen(fd, "w")) == NULL) {
		snprintf(err, errlen, "%s: %s", path, strerror(errno));
		EVP_PKEY_free(k);
		if (fd != -1)
			close(fd);
		return (-1);
	}
	if (PEM_write_PrivateKey(fp, k, NULL, NULL, 0, NULL, NULL) != 1 ||
	    fclose(fp) != 0) {
		(void)unlink(path);
		snprintf(err, errlen, "%s: the key was not written", path);
		EVP_PKEY_free(k);
		return (-1);
	}
	EVP_PKEY_free(k);
	return (0);
}

/* What is kept of name's pair and its SAs; NULL when nothing is. */
static ucl_object_t *
state_load(const char *name)
{
	struct ucl_parser	*p;
	ucl_object_t		*o;
	FILE			*fp;
	char			 path[MAXPATHLEN], buf[4096];
	size_t			 n;

	pair_path(STATE_FILE, name, path, sizeof(path));
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

static void
state_save(const char *name, const ucl_object_t *o)
{
	char	 path[MAXPATHLEN], *json;

	pair_path(STATE_FILE, name, path, sizeof(path));
	if ((json = (char *)ucl_object_emit(o, UCL_EMIT_JSON_COMPACT)) == NULL)
		return;
	if (file_replace(path, json, strlen(json), 0600) == -1)
		logmsg(LOG_WARNING, "%s: %s", path, strerror(errno));
	free(json);
}

static int64_t
num(const ucl_object_t *o, const char *key)
{
	const ucl_object_t	*v;

	v = o != NULL ? ucl_object_lookup(o, key) : NULL;
	return (v == NULL ? 0 : ucl_object_toint(v));
}

static void
state_put(ucl_object_t *o, const char *key, int64_t v)
{

	ucl_object_replace_key(o, ucl_object_fromint(v), key, 0, true);
}

/*
 * name's pair as its key-pair entry has it now (gen), which had it as
 * was before when had: made where there is none (one there already, the
 * ipsec-sa job's before 6.2.5, kept), made anew on another generation,
 * the one before kept; the one before put back on the generation it
 * had.  *how what was done, for sa_pair_unset(); -1 and why.
 */
int
sa_pair_set(const char *name, bool had, uint32_t was, uint32_t gen,
    int *how, char *err, size_t errlen)
{
	ucl_object_t	*st;
	char		 cur[MAXPATHLEN], prev[MAXPATHLEN], tmp[MAXPATHLEN];

	*how = SA_PAIR_KEPT;
	pair_path(KEY_FILE, name, cur, sizeof(cur));
	pair_path(PREV_FILE, name, prev, sizeof(prev));
	if ((st = state_load(name)) == NULL)
		st = ucl_object_typed_new(UCL_OBJECT);
	if (access(cur, F_OK) != 0) {
		if (pair_make(name, err, errlen) != 0) {
			ucl_object_unref(st);
			return (-1);
		}
		*how = SA_PAIR_MADE;
	} else if (had && gen != was) {
		if (access(prev, F_OK) == 0 && num(st, "prev_generation") ==
		    gen) {
			/* Back to the pair before: the two swapped. */
			snprintf(tmp, sizeof(tmp), "%s.swap", cur);
			if (rename(cur, tmp) != 0 || rename(prev, cur) != 0 ||
			    rename(tmp, prev) != 0) {
				snprintf(err, errlen, "%s: the pair before not put "
				    "back: %s", name, strerror(errno));
				ucl_object_unref(st);
				return (-1);
			}
			*how = SA_PAIR_BACK;
		} else {
			if (rename(cur, prev) != 0) {
				snprintf(err, errlen, "%s: %s", prev,
				    strerror(errno));
				ucl_object_unref(st);
				return (-1);
			}
			if (pair_make(name, err, errlen) != 0) {
				(void)rename(prev, cur);
				ucl_object_unref(st);
				return (-1);
			}
			*how = SA_PAIR_TURNED;
		}
		state_put(st, "prev_generation", was);
	}
	state_put(st, "generation", gen);
	state_save(name, st);
	ucl_object_unref(st);
	if (*how != SA_PAIR_KEPT)
		pair_told(name);
	return (0);
}

/* sa_pair_set() undone: the edit it was of refused. */
void
sa_pair_unset(const char *name, int how, uint32_t was, uint32_t gen)
{
	ucl_object_t	*st;
	char		 cur[MAXPATHLEN], prev[MAXPATHLEN], tmp[MAXPATHLEN];

	pair_path(KEY_FILE, name, cur, sizeof(cur));
	pair_path(PREV_FILE, name, prev, sizeof(prev));
	switch (how) {
	case SA_PAIR_MADE:
		(void)unlink(cur);
		pair_path(STATE_FILE, name, cur, sizeof(cur));
		(void)unlink(cur);
		return;
	case SA_PAIR_TURNED:
		(void)rename(prev, cur);
		break;
	case SA_PAIR_BACK:
		snprintf(tmp, sizeof(tmp), "%s.swap", cur);
		(void)rename(cur, tmp);
		(void)rename(prev, cur);
		(void)rename(tmp, prev);
		break;
	default:
		return;
	}
	if ((st = state_load(name)) != NULL) {
		state_put(st, "generation", was);
		state_put(st, "prev_generation", gen);
		state_save(name, st);
		ucl_object_unref(st);
	}
	pair_told(name);
}

/* name's pair gone with its key-pair entry: its files. */
void
sa_pair_drop(const char *name)
{
	char	path[MAXPATHLEN];

	pair_path(KEY_FILE, name, path, sizeof(path));
	(void)unlink(path);
	pair_path(PREV_FILE, name, path, sizeof(path));
	(void)unlink(path);
	pair_path(STATE_FILE, name, path, sizeof(path));
	(void)unlink(path);
}

/*
 * What name's derived SAs are, kept for the sdwan read and the console's
 * rotation: the newest outbound SA's SPI and since when (when another),
 * the inbound one's, the keys' lifetime, and whether two of a direction
 * are in (a rotation half done).
 */
void
sa_pair_state(const char *name, uint32_t spi_out, uint32_t spi_in,
    uint32_t lifetime, bool pending)
{
	ucl_object_t	*st;

	if ((st = state_load(name)) == NULL)
		st = ucl_object_typed_new(UCL_OBJECT);
	if (spi_out != 0 && num(st, "spi_out") != spi_out)
		state_put(st, "at", (int64_t)time(NULL));
	if (spi_out == 0)
		(void)ucl_object_delete_key(st, "at");
	state_put(st, "spi_out", spi_out);
	state_put(st, "spi_in", spi_in);
	state_put(st, "lifetime", lifetime);
	ucl_object_replace_key(st, ucl_object_frombool(pending), "pending", 0,
	    true);
	state_save(name, st);
	ucl_object_unref(st);
}

/*
 * The material of both directions from name's pair (prev, the pair
 * before a turn) and the far public half: HKDF-SHA256 of the X25519
 * agreement, salted, with both public halves in order and the epoch as
 * the info; the keys for A to B first.  *lower says this end is A.
 */
static int
derive_okm(const char *fmt, const char *name, const unsigned char *peer,
    const char *salt, uint32_t epoch, unsigned char *okm, size_t okmlen,
    bool *lower, char *err, size_t errlen)
{
	EVP_PKEY	*me, *far = NULL;
	EVP_PKEY_CTX	*ctx = NULL;
	EVP_KDF		*kdf;
	EVP_KDF_CTX	*kctx;
	OSSL_PARAM	 params[5];
	unsigned char	 shared[32], info[72], mypub[SA_PUB_LEN];
	size_t		 n;
	int		 rc = -1;

	if ((me = pair_load(fmt, name, err, errlen)) == NULL)
		return (-1);
	if (!pair_raw(me, mypub)) {
		EVP_PKEY_free(me);
		snprintf(err, errlen, "%s: the key is not an X25519 one", name);
		return (-1);
	}
	if (memcmp(mypub, peer, SA_PUB_LEN) == 0) {
		EVP_PKEY_free(me);
		snprintf(err, errlen, "%s: peer is this end's own public half",
		    name);
		return (-1);
	}
	*lower = memcmp(mypub, peer, SA_PUB_LEN) < 0;
	far = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer,
	    SA_PUB_LEN);
	ctx = far != NULL ? EVP_PKEY_CTX_new(me, NULL) : NULL;
	n = sizeof(shared);
	if (ctx == NULL || EVP_PKEY_derive_init(ctx) != 1 ||
	    EVP_PKEY_derive_set_peer(ctx, far) != 1 || EVP_PKEY_derive(ctx,
	    shared, &n) != 1 || n != sizeof(shared)) {
		snprintf(err, errlen, "%s: the agreement with the far public "
		    "half failed", name);
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
		snprintf(err, errlen, "%s: HKDF gave no keys", name);
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

/* An SPI from four bytes: 256 or more. */
static uint32_t
spi_of(const unsigned char *b)
{
	uint32_t	n;

	n = (uint32_t)b[0] << 24 | (uint32_t)b[1] << 16 | (uint32_t)b[2] << 8 |
	    b[3];
	return (n < 256 ? n + 256 : n);
}

/*
 * One direction's SA from name's pair and the far half peer: its SPI,
 * its encryption key of enclen bytes (AES-GCM's salt after it) into ek,
 * its integrity key of authlen (0: none, AEAD) into ak.  The material
 * is enc A to B, auth A to B, enc B to A, auth B to A, then the two
 * SPIs, A to B's first: what the ipsec-sa job derived before 6.2.5, so
 * a tunnel keyed by it keeps its SAs.  0, or -1 and why.
 */
int
sa_pair_derive(const char *name, const unsigned char peer[SA_PUB_LEN],
    uint32_t epoch, bool outbound, size_t enclen, size_t authlen,
    uint32_t *spi, unsigned char *ek, unsigned char *ak, char *err,
    size_t errlen)
{
	unsigned char	okm[2 * (36 + 64) + 8];
	size_t		at;
	bool		lower, ab;
	uint32_t	other;

	if (enclen > 36 || authlen > 64) {
		snprintf(err, errlen, "%s: keys too long to derive", name);
		return (-1);
	}
	if (derive_okm(KEY_FILE, name, peer, HKDF_SALT, epoch, okm, 2 *
	    (enclen + authlen) + 8, &lower, err, errlen) != 0)
		return (-1);
	/* A to B is A's outbound, B's inbound. */
	ab = lower == outbound;
	at = ab ? 0 : enclen + authlen;
	memcpy(ek, okm + at, enclen);
	if (authlen > 0)
		memcpy(ak, okm + at + enclen, authlen);
	at = 2 * (enclen + authlen);
	*spi = spi_of(okm + at + (ab ? 0 : 4));
	other = spi_of(okm + at + (ab ? 4 : 0));
	/* The two directions never of one SPI (the job's way). */
	if (*spi == other && !ab)
		*spi ^= 1;
	OPENSSL_cleanse(okm, sizeof(okm));
	return (0);
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
	unsigned char	peer[33];
	char		err[200];
	bool		lower;

	if (strlen(peer_b64) != PUB_B64 || EVP_DecodeBlock(peer,
	    (const unsigned char *)peer_b64, PUB_B64) < 32) {
		*errp = "peer is the far end's public half, 44 characters of "
		    "base64";
		return (-1);
	}
	if (derive_okm(KEY_FILE, sa_ifkey(w, ifname), peer, salt, 0, okm,
	    okmlen, &lower, err, sizeof(err)) != 0) {
		*errp = wstrdup(w, err);
		return (-1);
	}
	return (0);
}

/* The public halves this host keeps, for the sdwan read: keys, each an
 * interface (a vnet jail's as "ipsec0@web"), its public, its pair's
 * generation, and what its derived SAs are (keyed_at, lifetime, spi_in,
 * spi_out, pending). */
void
sa_keys_json(struct work *w, ucl_object_t *top)
{
	ucl_object_t	*arr, *o, *stt;
	EVP_PKEY	*k;
	DIR		*d;
	struct dirent	*de;
	char		 dir[MAXPATHLEN], pub[PUB_B64 + 1], *slash, e[160],
			 ifn[32 + MAXHOSTNAMELEN];
	size_t		 n;

	(void)w;
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
			    n - 14 >= sizeof(ifn) || (n > 19 && (strcmp(
			    de->d_name + n - 9, "-next.pem") == 0 || strcmp(
			    de->d_name + n - 9, "-prev.pem") == 0)))
				continue;
			snprintf(ifn, sizeof(ifn), "%.*s", (int)(n - 14),
			    de->d_name + 10);
			if ((k = pair_load(KEY_FILE, ifn, e, sizeof(e))) == NULL)
				continue;
			if (pair_b64(k, pub, sizeof(pub))) {
				o = ucl_object_typed_new(UCL_OBJECT);
				ucl_object_insert_key(o, ucl_object_fromstring(ifn),
				    "interface", 0, false);
				ucl_object_insert_key(o, ucl_object_fromstring(pub),
				    "public", 0, false);
				if ((stt = state_load(ifn)) != NULL) {
					static const char *const nums[] = { "at",
					    "lifetime", "spi_in", "spi_out",
					    "generation" };

					for (size_t i = 0; i < nitems(nums); i++)
						if (num(stt, nums[i]) != 0)
							ucl_object_insert_key(o,
							    ucl_object_fromint(num(stt,
							    nums[i])), i == 0 ?
							    "keyed_at" : nums[i], 0,
							    false);
					ucl_object_insert_key(o, ucl_object_frombool(
					    ucl_object_toboolean(ucl_object_lookup(
					    stt, "pending"))), "pending", 0, false);
					ucl_object_unref(stt);
				}
				ucl_array_append(arr, o);
			}
			EVP_PKEY_free(k);
		}
		closedir(d);
	}
	ucl_object_insert_key(top, arr, "keys", 0, false);
}

static const char *
sstr(const ucl_object_t *o, const char *key)
{
	const ucl_object_t	*v;

	v = o != NULL ? ucl_object_lookup(o, key) : NULL;
	return (v != NULL && ucl_object_type(v) == UCL_STRING ?
	    ucl_object_tostring(v) : NULL);
}

/*
 * The key-rotation faults held to the pairs there are (sa_keys_json()'s):
 * one of a pair gone cleared; with at_start, one of a pair no longer
 * turning its keys (none pending) too, its cause gone with the agent
 * before.  Between, a failed rotation's stays until one is done.
 */
static void
sa_reconcile(bool at_start)
{
	struct fault_live	*v;
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	ucl_object_t		*top;
	struct work		 w;
	size_t			 n;

	work_init(&w);
	top = ucl_object_typed_new(UCL_OBJECT);
	sa_keys_json(&w, top);
	n = ucl_array_size(ucl_object_lookup(top, "keys"));
	if ((v = calloc(n + 1, sizeof(*v))) == NULL) {
		ucl_object_unref(top);
		work_free(&w);
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
	work_free(&w);
}

/* At the start: the rotations' faults held to the keys there are. */
void
sa_faults_start(void)
{

	sa_reconcile(true);
}

/*
 * After an edit of the lists: a pair whose derived SAs an edit could not
 * change has a key-rotation fault (why), until an edit leaves it one SA
 * a direction (why NULL); the faults held to the pairs there are.
 */
void
sa_rotation_fault(const char *name, const char *why)
{

	if (name != NULL && why != NULL)
		fault_set("key-rotation", "Major", name, "arcana-agent",
		    "the keys of %s were not turned: %s", name, why);
	else if (name != NULL)
		fault_clear("key-rotation", name, "the keys of %s turned", name);
	else
		sa_reconcile(false);
}
