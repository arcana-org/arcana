/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: RFC 9061's IKE-less lists (ietf-i2nsf-ikeless's ipsec-ikeless,
 * PLAN-SDN-YANG 6.2.4), the kernel's SAD and SPD by PF_KEY (pfkey.c).
 *
 * Running holds the controller's entries, kept beside the agent's
 * files (IKL_FILE, 0600: the keys are in it), each put in as it is
 * configured: an sad-entry by SADB_ADD and read back by SADB_GET, an
 * spd-entry by SADB_X_SPDADD (SADB_X_SPDUPDATE where an entry of the
 * same selector and direction is changed, so its traffic is never sent
 * plain meanwhile).  An edit changes what differs between running and
 * the new configuration alone, policies taken out first, then SAs, then
 * the new SAs put in, then their policies; one step refused undoes the
 * steps before it, the kernel and running as they were.
 *
 * The operational datastore is the kernel's: every ESP SA (SADB_DUMP) and
 * every policy (SADB_X_SPDDUMP) of the host's network.  The controller's
 * are named as it named them; the rest, setkey(8)'s and so ipsec.conf's,
 * an IKE daemon's, an ipsec(4) interface's own, the agent's manual SAs
 * and their policies (arcana-jobs' ipsec-sa, sa.c), by the kernel's own
 * key: an SA "esp/<destination>/0x<SPI>", a policy "spd/<id>".  Those
 * are never in running, so no edit touches them: an entry of the
 * controller's that would take one's SPI and destination, or one's
 * selector and direction, is refused (in-use) before anything is
 * changed.  A policy is the controller's by its priority, from
 * IKL_SP_BASE in the list's order (ordered-by user: the first wins),
 * after setkey's (0) and before the ipsec-sa job's (PFKEY_SP_MARK); an
 * SA by its SPI and destination being one of running's.
 *
 * The mapping.  An SA is from its local end to its remote one: in tunnel
 * mode the tunnel's local and remote, in transport mode the traffic
 * selector's local and remote prefixes, each a single address; a
 * selector's local prefix is the packets' source and the remote their
 * destination, whichever the direction, as RFC 9061 Appendix B writes
 * its inbound entries (so the tunnel's local of an inbound policy is the
 * peer's address).  protect is IPSEC_POLICY_IPSEC with one ESP request,
 * at level unique on the entry's reqid or, of reqid 0, require; bypass
 * IPSEC_POLICY_NONE; discard IPSEC_POLICY_DISCARD.  ext-seq-num is
 * SADB_X_SAFLAGS_ESN; seq-overflow, the counter allowed to wrap,
 * SADB_X_EXT_CYCSEQ; the window in packets, by eights (the kernel's
 * bytes); IANA's ENCR_AES_CBC (12) and ENCR_AES_GCM_16 (20, its salt the
 * key's last four bytes or the iv), AUTH_HMAC_SHA1_96 (2) and
 * AUTH_HMAC_SHA2_256_128, _384_192, _512_256 (12, 13, 14); espinudp
 * NAT-T's ESP in UDP on its ports.  sa-lifetime-soft and -hard are the
 * kernel's SADB_EXT_LIFETIME_SOFT and _HARD: time its addtime, bytes its
 * bytes; packets (allocations, counted by the kernel but not enforced)
 * and idle (the kernel has the first use alone) are the agent's, read
 * with the counters every 10 s (sadb.c): reached soft, sadb-expire told
 * once; hard, the SA taken out by SADB_DELETE and sadb-expire told.
 * What the policy's ipsec-sa-cfg says of the SAs to make (algorithms,
 * ESN, window, tfc) is the controller's, kept, not the kernel's: an
 * IKE-less policy is given its SAs.
 *
 * Refused (operation-not-supported): what FreeBSD's IPsec does not do:
 * espintcp, original addresses of NAT-T, df-bit but clear (one sysctl
 * for all SAs, net.inet.ipsec.dfbit), DSCP mappings and filtering,
 * pfp-flag, a port range that is neither one port nor all, another
 * algorithm.  Refused (invalid-value): what does not hold together: a
 * reqid over IPSEC_MANUAL_REQID_MAX, an SPI under 256, families mixed,
 * a transport SA's prefix not one address, ESN without a window (its
 * high bits are kept in it), seq-overflow with AEAD (RFC 9061), keys of
 * the wrong length, AES-CBC without integrity, a name of the kernel's
 * form, two entries of one SA or one selector.
 *
 * State loss (RFC 9061 4.2): at the start the controller's policies are
 * put back where the kernel has not got them, so traffic is not sent
 * plain; its SAs gone with a reboot are not (their sequence numbers
 * would start again under the old keys), they leave running, and the
 * controller sends new ones (sadb-acquire tells it which are wanted).
 * The host's network only: no jail's.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>

#include <net/pfkeyv2.h>
#include <netinet/in.h>
#include <netipsec/ipsec.h>

#include <arpa/inet.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <openssl/crypto.h>

#include <cblink.h>
#include <cbl_schema.h>

#include "agent.h"
#include "collect.h"

#define	IKL_FILE	"ikeless.cbor"
#define	IKL_FILE_MAX	(1024 * 1024)
#define	IKL_SP_BASE	0x7fa20000u	/* the first spd-entry's priority */
#define	IKL_MAX		1024		/* entries a list takes */
#define	IKL_NAME	256		/* the longest name taken */
#define	IKL_KEY		64		/* the longest key, bytes */

typedef struct ietf_i2nsf_ikeless_ipsec_ikeless yikl;
typedef struct ietf_i2nsf_ikeless_ipsec_ikeless_sad ysad;
typedef struct ietf_i2nsf_ikeless_ipsec_ikeless_spd yspd;
typedef struct ietf_i2nsf_ikeless_ipsec_ikeless_sad_sad_entry ysa;
typedef struct ietf_i2nsf_ikeless_ipsec_ikeless_sad_sad_entry_ipsec_sa_config
    ysacfg;
typedef struct ietf_i2nsf_ikeless_ipsec_ikeless_sad_sad_entry_ipsec_sa_config_esp_sa
    yespsa;
typedef struct ietf_i2nsf_ikeless_ipsec_ikeless_sad_sad_entry_ipsec_sa_config_esp_sa_encryption
    yenc;
typedef struct ietf_i2nsf_ikeless_ipsec_ikeless_sad_sad_entry_ipsec_sa_config_esp_sa_integrity
    yint;
typedef struct ietf_i2nsf_ikeless_ipsec_ikeless_sad_sad_entry_ipsec_sa_config_traffic_selector
    ysats;
typedef struct ietf_i2nsf_ikeless_ipsec_ikeless_sad_sad_entry_ipsec_sa_config_tunnel
    ysatun;
typedef struct ietf_i2nsf_ikeless_ipsec_ikeless_sad_sad_entry_ipsec_sa_config_encapsulation_type
    yencap;
typedef struct ietf_i2nsf_ikeless_ipsec_ikeless_sad_sad_entry_ipsec_sa_config_sa_lifetime_hard
    yhard;
typedef struct ietf_i2nsf_ikeless_ipsec_ikeless_sad_sad_entry_ipsec_sa_config_sa_lifetime_soft
    ysoft;
typedef struct ietf_i2nsf_ikeless_ipsec_ikeless_sad_sad_entry_ipsec_sa_state
    ysastate;
typedef struct ietf_i2nsf_ikeless_ipsec_ikeless_sad_sad_entry_ipsec_sa_state_sa_lifetime_current
    ycur;
typedef struct ietf_i2nsf_ikeless_ipsec_ikeless_sad_sad_entry_ipsec_sa_state_replay_stats
    yreplay;
typedef struct ietf_i2nsf_ikeless_ipsec_ikeless_sad_sad_entry_ipsec_sa_state_replay_stats_replay_window
    ywin;
typedef struct ietf_i2nsf_ikeless_ipsec_ikeless_spd_spd_entry ysp;
typedef struct ietf_i2nsf_ikeless_ipsec_ikeless_spd_spd_entry_ipsec_policy_config
    yspcfg;
typedef struct ietf_i2nsf_ikeless_ipsec_ikeless_spd_spd_entry_ipsec_policy_config_traffic_selector
    ytsel;
typedef struct ietf_i2nsf_ikeless_ipsec_ikeless_spd_spd_entry_ipsec_policy_config_traffic_selector_local_ports
    yports;
typedef struct ietf_i2nsf_ikeless_ipsec_ikeless_spd_spd_entry_ipsec_policy_config_processing_info
    yproc;
typedef struct ietf_i2nsf_ikeless_ipsec_ikeless_spd_spd_entry_ipsec_policy_config_processing_info_ipsec_sa_cfg
    ysacfg2;
typedef struct ietf_i2nsf_ikeless_ipsec_ikeless_spd_spd_entry_ipsec_policy_config_processing_info_ipsec_sa_cfg_tunnel
    ysptun;

#define	SA_MODE_TUNNEL	IETF_I2NSF_IKELESS_IPSEC_IKELESS_SAD_SAD_ENTRY_IPSEC_SA_CONFIG_MODE_TUNNEL
#define	SP_MODE_TUNNEL	IETF_I2NSF_IKELESS_IPSEC_IKELESS_SPD_SPD_ENTRY_IPSEC_POLICY_CONFIG_PROCESSING_INFO_IPSEC_SA_CFG_MODE_TUNNEL
#define	SP_MODE_TRANSPORT IETF_I2NSF_IKELESS_IPSEC_IKELESS_SPD_SPD_ENTRY_IPSEC_POLICY_CONFIG_PROCESSING_INFO_IPSEC_SA_CFG_MODE_TRANSPORT
#define	SA_MODE_TRANSPORT IETF_I2NSF_IKELESS_IPSEC_IKELESS_SAD_SAD_ENTRY_IPSEC_SA_CONFIG_MODE_TRANSPORT
#define	SP_INBOUND	IETF_I2NSF_IKELESS_IPSEC_IKELESS_SPD_SPD_ENTRY_DIRECTION_INBOUND
#define	SP_OUTBOUND	IETF_I2NSF_IKELESS_IPSEC_IKELESS_SPD_SPD_ENTRY_DIRECTION_OUTBOUND
#define	SP_PROTECT	IETF_I2NSF_IKELESS_IPSEC_IKELESS_SPD_SPD_ENTRY_IPSEC_POLICY_CONFIG_PROCESSING_INFO_ACTION_PROTECT
#define	SP_BYPASS	IETF_I2NSF_IKELESS_IPSEC_IKELESS_SPD_SPD_ENTRY_IPSEC_POLICY_CONFIG_PROCESSING_INFO_ACTION_BYPASS
#define	SP_DISCARD	IETF_I2NSF_IKELESS_IPSEC_IKELESS_SPD_SPD_ENTRY_IPSEC_POLICY_CONFIG_PROCESSING_INFO_ACTION_DISCARD
#define	SA_PROTO_ANY	IETF_I2NSF_IKELESS_IPSEC_IKELESS_SAD_SAD_ENTRY_IPSEC_SA_CONFIG_TRAFFIC_SELECTOR_INNER_PROTOCOL_M1_ANY
#define	SP_PROTO_ANY	IETF_I2NSF_IKELESS_IPSEC_IKELESS_SPD_SPD_ENTRY_IPSEC_POLICY_CONFIG_TRAFFIC_SELECTOR_INNER_PROTOCOL_M1_ANY
#define	ENCAP_UDP	IETF_I2NSF_IKELESS_IPSEC_IKELESS_SAD_SAD_ENTRY_IPSEC_SA_CONFIG_ENCAPSULATION_TYPE_ESPENCAP_ESPINUDP
#define	ENCAP_TCP	IETF_I2NSF_IKELESS_IPSEC_IKELESS_SAD_SAD_ENTRY_IPSEC_SA_CONFIG_ENCAPSULATION_TYPE_ESPENCAP_ESPINTCP
#define	SA_DF_CLEAR	IETF_I2NSF_IKELESS_IPSEC_IKELESS_SAD_SAD_ENTRY_IPSEC_SA_CONFIG_TUNNEL_DF_BIT_CLEAR
#define	SP_DF_CLEAR	IETF_I2NSF_IKELESS_IPSEC_IKELESS_SPD_SPD_ENTRY_IPSEC_POLICY_CONFIG_PROCESSING_INFO_IPSEC_SA_CFG_TUNNEL_DF_BIT_CLEAR

/* IANA's IKEv2 transform numbers (RFC 9061's encr-alg-t, intr-alg-t). */
#define	IANA_ENCR_AES_CBC	12
#define	IANA_ENCR_AES_GCM_16	20

static const struct {
	uint16_t	iana;
	uint8_t		alg;		/* PF_KEY's */
	size_t		keylen[3];	/* bytes, 0 ends */
	bool		aead;
} encs[] = {
	{ IANA_ENCR_AES_CBC, SADB_X_EALG_AESCBC, { 16, 24, 32 }, false },
	/* The key and its four bytes of salt, as one. */
	{ IANA_ENCR_AES_GCM_16, SADB_X_EALG_AESGCM16, { 20, 28, 36 }, true },
}, ints[] = {
	{ 2, SADB_AALG_SHA1HMAC, { 20 }, false },
	{ 12, SADB_X_AALG_SHA2_256, { 32 }, false },
	{ 13, SADB_X_AALG_SHA2_384, { 48 }, false },
	{ 14, SADB_X_AALG_SHA2_512, { 64 }, false },
};

/* The kernel's algorithms as IANA numbers them, for what is read. */
static const struct {
	uint8_t		alg;
	uint16_t	iana;
} kencs[] = {
	{ SADB_EALG_NULL, 11 }, { SADB_X_EALG_AESCBC, 12 },
	{ SADB_X_EALG_AESCTR, 13 }, { SADB_X_EALG_AESGCM8, 18 },
	{ SADB_X_EALG_AESGCM12, 19 }, { SADB_X_EALG_AESGCM16, 20 },
	{ SADB_X_EALG_AESGMAC, 21 }, { SADB_X_EALG_CHACHA20POLY1305, 28 },
}, kints[] = {
	{ SADB_AALG_NONE, 0 }, { SADB_AALG_MD5HMAC, 1 },
	{ SADB_AALG_SHA1HMAC, 2 }, { SADB_X_AALG_AES_XCBC_MAC, 5 },
	{ SADB_X_AALG_SHA2_256, 12 }, { SADB_X_AALG_SHA2_384, 13 },
	{ SADB_X_AALG_SHA2_512, 14 },
};

/* An sad-entry as the kernel is given it. */
struct ikl_sa {
	const char	*name;
	struct pfkey_sa	 sa;
	unsigned char	 ek[IKL_KEY], ak[IKL_KEY];
	uint32_t	 idle_soft, idle_hard;	/* the agent's, seconds */
	bool		 aead;
};

/* An spd-entry as the kernel is given it. */
struct ikl_sp {
	const char	*name;
	struct pfkey_sp	 sp;
};

struct ikl_set {
	struct ikl_sa	*sa;
	size_t		 nsa;
	struct ikl_sp	*sp;
	size_t		 nsp;
};

/* Why an edit is refused: the message, the node at fault, the errno. */
struct iklerr {
	char		 msg[512];
	uint64_t	 sid;
	int		 error;
};

static pthread_mutex_t	ikl_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * What the news and the counters need of running's entries (sadb.c):
 * each SA's name, its ends, SPI and the lifetimes that are the agent's;
 * each policy's name and selector.  Rebuilt when running changes.
 */
struct ikl_live {
	char			*name;
	struct sockaddr_storage	 dst;
	uint32_t		 spi;
	uint32_t		 idle_soft, idle_hard;
	uint64_t		 bytes;		/* when last read */
	time_t			 moved;		/* and when they last moved */
	bool			 told_soft;
};
static pthread_mutex_t	 live_lock = PTHREAD_MUTEX_INITIALIZER;
static struct ikl_live	*live_sa;
static size_t		 nlive_sa;
static struct ikl_sp	*live_sp;
static size_t		 nlive_sp;

static const struct cbl_ynode *
ikl_node(void)
{

	return (ynode_named("ietf-i2nsf-ikeless", "ipsec-ikeless"));
}

static int __printflike(4, 5)
fault(struct iklerr *ie, int error, const char *node, const char *fmt, ...)
{
	const struct cbl_ynode	*n;
	va_list			 ap;

	va_start(ap, fmt);
	vsnprintf(ie->msg, sizeof(ie->msg), fmt, ap);
	va_end(ap);
	ie->error = error;
	n = node != NULL ? ynet_node("ietf-i2nsf-ikeless", "ipsec-ikeless",
	    node) : NULL;
	ie->sid = n != NULL ? n->sid : 0;
	return (-1);
}

/* ---- Words ----------------------------------------------------------- */

/* An address as a sockaddr, port 0; false when it is not one (a zone
 * is not taken). */
static bool
addr_of(const char *s, struct sockaddr_storage *ss)
{
	struct sockaddr_in	*sin = (struct sockaddr_in *)ss;
	struct sockaddr_in6	*sin6 = (struct sockaddr_in6 *)ss;

	memset(ss, 0, sizeof(*ss));
	if (s == NULL)
		return (false);
	if (inet_pton(AF_INET, s, &sin->sin_addr) == 1) {
		sin->sin_len = sizeof(*sin);
		sin->sin_family = AF_INET;
		return (true);
	}
	if (inet_pton(AF_INET6, s, &sin6->sin6_addr) == 1) {
		sin6->sin6_len = sizeof(*sin6);
		sin6->sin6_family = AF_INET6;
		return (true);
	}
	return (false);
}

static unsigned
addr_max(const struct sockaddr_storage *ss)
{

	return (ss->ss_family == AF_INET6 ? 128 : 32);
}

/* A prefix (address/length) as a sockaddr and its length. */
static bool
prefix_of(const char *s, struct sockaddr_storage *ss, uint8_t *plen)
{
	char		 a[INET6_ADDRSTRLEN + 8], *sl, *end;
	unsigned long	 n;

	if (s == NULL || strlcpy(a, s, sizeof(a)) >= sizeof(a) ||
	    (sl = strchr(a, '/')) == NULL)
		return (false);
	*sl++ = '\0';
	if (!addr_of(a, ss))
		return (false);
	n = strtoul(sl, &end, 10);
	if (*sl == '\0' || *end != '\0' || n > addr_max(ss))
		return (false);
	*plen = (uint8_t)n;
	return (true);
}

static void
port_set(struct sockaddr_storage *ss, uint16_t port)
{

	if (ss->ss_family == AF_INET6)
		((struct sockaddr_in6 *)ss)->sin6_port = htons(port);
	else
		((struct sockaddr_in *)ss)->sin_port = htons(port);
}

static uint16_t
port_get(const struct sockaddr_storage *ss)
{
	const void	*v = ss;

	if (ss->ss_family == AF_INET6)
		return (ntohs(((const struct sockaddr_in6 *)v)->sin6_port));
	if (ss->ss_family == AF_INET)
		return (ntohs(((const struct sockaddr_in *)v)->sin_port));
	return (0);
}

static void
addr_text(const struct sockaddr_storage *ss, char *b, size_t len)
{
	const void	*v = ss;

	b[0] = '\0';
	if (ss->ss_family == AF_INET)
		inet_ntop(AF_INET, &((const struct sockaddr_in *)v)->sin_addr,
		    b, len);
	else if (ss->ss_family == AF_INET6)
		inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)v)->
		    sin6_addr, b, len);
}

/* Whether two addresses are one, their ports aside. */
static bool
addr_same(const struct sockaddr_storage *a, const struct sockaddr_storage *b)
{
	const void	*va = a, *vb = b;

	if (a->ss_family != b->ss_family)
		return (false);
	if (a->ss_family == AF_INET)
		return (((const struct sockaddr_in *)va)->sin_addr.s_addr ==
		    ((const struct sockaddr_in *)vb)->sin_addr.s_addr);
	if (a->ss_family == AF_INET6)
		return (memcmp(&((const struct sockaddr_in6 *)va)->sin6_addr,
		    &((const struct sockaddr_in6 *)vb)->sin6_addr,
		    sizeof(struct in6_addr)) == 0);
	return (false);
}

static int
nibble(char c)
{

	if (c >= '0' && c <= '9')
		return (c - '0');
	if (c >= 'a' && c <= 'f')
		return (c - 'a' + 10);
	if (c >= 'A' && c <= 'F')
		return (c - 'A' + 10);
	return (-1);
}

/* A hex-string (yang-types': 01:23:ab, the colons optional here) as
 * bytes; -1 when it is not one or is longer than max. */
static ssize_t
hex_of(const char *s, unsigned char *out, size_t max)
{
	size_t	n = 0;
	int	hi, lo;

	while (*s != '\0') {
		if (*s == ':') {
			s++;
			continue;
		}
		if ((hi = nibble(s[0])) == -1 || (lo = nibble(s[1])) == -1 ||
		    n == max)
			return (-1);
		out[n++] = (unsigned char)(hi << 4 | lo);
		s += 2;
	}
	return ((ssize_t)n);
}

static bool
len_in(size_t n, const size_t *lens)
{

	for (size_t i = 0; i < 3 && lens[i] != 0; i++)
		if (lens[i] == n)
			return (true);
	return (false);
}

/* A name the kernel's form would take for one of its own. */
static bool
name_kernels(const char *s)
{

	return (strncmp(s, "esp/", 4) == 0 || strncmp(s, "spd/", 4) == 0);
}

/* The ports of a selector's end: none, one, or all of them. */
static int
ports_of(size_t n, const yports *v, uint16_t *port, struct iklerr *ie,
    const char *node, const char *name, const char *which)
{

	*port = 0;
	if (n == 0)
		return (0);
	if (n > 1)
		return (fault(ie, EOPNOTSUPP, node, "%s: %s ports: more than "
		    "one range; the kernel's selector holds one port or all",
		    name, which));
	if (v[0].start == 0 && (v[0].end == 0 || v[0].end == 65535))
		return (0);
	if (v[0].start != v[0].end)
		return (fault(ie, EOPNOTSUPP, node, "%s: %s ports %u-%u: the "
		    "kernel's selector holds one port or all", name, which,
		    v[0].start, v[0].end));
	*port = v[0].start;
	return (0);
}

/* ---- Compiled -------------------------------------------------------- */

static int
lifetime_of(struct ikl_sa *k, const ysoft *s, const yhard *h,
    struct iklerr *ie, const char *name)
{

	if (s != NULL) {
		k->sa.soft.time = s->has_time ? s->time : 0;
		k->sa.soft.bytes = s->has_bytes ? s->bytes : 0;
		k->sa.soft.packets = s->has_packets ? s->packets : 0;
		k->idle_soft = s->has_idle ? s->idle : 0;
	}
	if (h != NULL) {
		k->sa.hard.time = h->has_time ? h->time : 0;
		k->sa.hard.bytes = h->has_bytes ? h->bytes : 0;
		k->sa.hard.packets = h->has_packets ? h->packets : 0;
		k->idle_hard = h->has_idle ? h->idle : 0;
	}
	if (k->sa.soft.time != 0 || k->sa.soft.bytes != 0 ||
	    k->sa.soft.packets != 0 || k->sa.hard.time != 0 ||
	    k->sa.hard.bytes != 0 || k->sa.hard.packets != 0)
		k->sa.lifetimes = PFKEY_LT_SOFT | PFKEY_LT_HARD;
	(void)ie;
	(void)name;
	return (0);
}

/* An sad-entry as the kernel is to have it, or why not. */
static int
sa_compile(const ysa *e, struct ikl_sa *k, struct iklerr *ie)
{
	const ysacfg	*c = e->ipsec_sa_config;
	const yenc	*en;
	const yint	*in;
	const ysats	*ts;
	const ysatun	*tu;
	const yencap	*ec;
	unsigned char	 iv[8];
	uint8_t		 pl;
	uint16_t	 ealg, aalg;
	ssize_t		 n;
	size_t		 i, j;
	uint32_t	 win;
	bool		 tunnel, esn;
	const char	*name = e->name;

	memset(k, 0, sizeof(*k));
	k->name = name;
	if (strlen(name) >= IKL_NAME || name[0] == '\0')
		return (fault(ie, EINVAL, "sad/sad-entry/name", "sad-entry "
		    "\"%.40s\": a name of 1 to %d characters", name,
		    IKL_NAME - 1));
	if (name_kernels(name))
		return (fault(ie, EINVAL, "sad/sad-entry/name", "%s: esp/ and "
		    "spd/ name the kernel's own entries", name));
	if (c == NULL || !c->has_spi)
		return (fault(ie, EINVAL, "sad/sad-entry/ipsec-sa-config/spi",
		    "%s: no SPI", name));
	if (c->spi < 256)
		return (fault(ie, EINVAL, "sad/sad-entry/ipsec-sa-config/spi",
		    "%s: SPI %u: 1 to 255 are reserved (RFC 4303)", name,
		    c->spi));
	k->sa.spi = c->spi;
	if (e->has_reqid && e->reqid > IPSEC_MANUAL_REQID_MAX)
		return (fault(ie, EINVAL, "sad/sad-entry/reqid", "%s: reqid "
		    "%ju: a manual one is 1 to %d", name, (uintmax_t)e->reqid,
		    IPSEC_MANUAL_REQID_MAX));
	k->sa.reqid = e->has_reqid ? (uint32_t)e->reqid : 0;
	tunnel = c->has_mode && c->mode == SA_MODE_TUNNEL;
	k->sa.mode = tunnel ? IPSEC_MODE_TUNNEL : IPSEC_MODE_TRANSPORT;
	/* Its ends. */
	if (tunnel) {
		tu = c->tunnel;
		if (tu == NULL || !tu->has_local || !tu->has_remote ||
		    !addr_of(tu->local.v.m0, &k->sa.src) ||
		    !addr_of(tu->remote.v.m0, &k->sa.dst))
			return (fault(ie, EINVAL, "sad/sad-entry/ipsec-sa-config/"
			    "tunnel", "%s: tunnel mode needs the tunnel's "
			    "local and remote addresses", name));
		if (tu->has_df_bit && tu->df_bit != SA_DF_CLEAR)
			return (fault(ie, EOPNOTSUPP, "sad/sad-entry/"
			    "ipsec-sa-config/tunnel/df-bit", "%s: df-bit: "
			    "FreeBSD sets it for all SAs at once "
			    "(net.inet.ipsec.dfbit), not per SA", name));
		if ((tu->has_bypass_dscp && !tu->bypass_dscp) ||
		    tu->dscp_mapping.n > 0 || tu->dscp_values.n > 0)
			return (fault(ie, EOPNOTSUPP, "sad/sad-entry/"
			    "ipsec-sa-config/tunnel/dscp-mapping", "%s: DSCP "
			    "mappings and filtering: FreeBSD's SAs have none",
			    name));
	} else {
		ts = c->traffic_selector;
		if (ts == NULL || !ts->has_local_prefix ||
		    !ts->has_remote_prefix ||
		    !prefix_of(ts->local_prefix.v.m0, &k->sa.src, &pl) ||
		    pl != addr_max(&k->sa.src) ||
		    !prefix_of(ts->remote_prefix.v.m0, &k->sa.dst, &pl) ||
		    pl != addr_max(&k->sa.dst))
			return (fault(ie, EINVAL, "sad/sad-entry/ipsec-sa-config/"
			    "traffic-selector", "%s: a transport mode SA is "
			    "between the two addresses of its selector, each "
			    "a prefix of one address", name));
	}
	if (k->sa.src.ss_family != k->sa.dst.ss_family)
		return (fault(ie, EINVAL, "sad/sad-entry/ipsec-sa-config", "%s: "
		    "its local and remote addresses are of two families",
		    name));
	/* The window, ESN, the counter's wrap. */
	win = c->has_anti_replay_window_size ? c->anti_replay_window_size : 64;
	if (win % 8 != 0)
		return (fault(ie, EINVAL, "sad/sad-entry/ipsec-sa-config/"
		    "anti-replay-window-size", "%s: a window of %u packets: "
		    "the kernel's is in bytes, a multiple of 8 packets", name,
		    win));
	k->sa.replay = win / 8;
	esn = c->has_ext_seq_num ? c->ext_seq_num : true;
	if (esn && win == 0)
		return (fault(ie, EINVAL, "sad/sad-entry/ipsec-sa-config/"
		    "ext-seq-num", "%s: ESN needs an anti-replay window: the "
		    "kernel keeps the high bits in it", name));
	k->sa.flags = (esn ? SADB_X_SAFLAGS_ESN : 0) |
	    (c->has_seq_overflow && c->seq_overflow ? SADB_X_EXT_CYCSEQ : 0);
	/* The algorithms and keys. */
	en = c->esp_sa != NULL ? c->esp_sa->encryption : NULL;
	in = c->esp_sa != NULL ? c->esp_sa->integrity : NULL;
	ealg = en != NULL && en->has_encryption_algorithm ?
	    en->encryption_algorithm : IANA_ENCR_AES_CBC;
	for (i = 0; i < nitems(encs) && encs[i].iana != ealg; i++)
		;
	if (i == nitems(encs))
		return (fault(ie, EOPNOTSUPP, "sad/sad-entry/ipsec-sa-config/"
		    "esp-sa/encryption/encryption-algorithm", "%s: encryption "
		    "%u: taken are 12 (AES-CBC) and 20 (AES-GCM-16)", name,
		    ealg));
	k->sa.ealg = encs[i].alg;
	k->aead = encs[i].aead;
	if (en == NULL || en->key == NULL || (n = hex_of(en->key, k->ek,
	    sizeof(k->ek))) <= 0)
		return (fault(ie, EINVAL, "sad/sad-entry/ipsec-sa-config/esp-sa/"
		    "encryption/key", "%s: no encryption key, or one not hex",
		    name));
	/* AES-GCM's salt: the key's last four bytes, or the iv. */
	if (k->aead && en->iv != NULL && !len_in((size_t)n, encs[i].keylen)) {
		if (hex_of(en->iv, iv, sizeof(iv)) != 4 || (size_t)n + 4 >
		    sizeof(k->ek))
			return (fault(ie, EINVAL, "sad/sad-entry/"
			    "ipsec-sa-config/esp-sa/encryption/iv", "%s: "
			    "AES-GCM's iv, its salt, is 4 bytes", name));
		memcpy(k->ek + n, iv, 4);
		n += 4;
	}
	if (!len_in((size_t)n, encs[i].keylen))
		return (fault(ie, EINVAL, "sad/sad-entry/ipsec-sa-config/esp-sa/"
		    "encryption/key", "%s: an encryption key of %zd bytes: "
		    "%s takes %zu, %zu or %zu", name, n, k->aead ?
		    "AES-GCM-16 with its salt" : "AES-CBC", encs[i].keylen[0],
		    encs[i].keylen[1], encs[i].keylen[2]));
	k->sa.ekeylen = (size_t)n;
	k->sa.aalg = SADB_AALG_NONE;
	if (k->aead) {
		if (c->has_seq_overflow && c->seq_overflow)
			return (fault(ie, EINVAL, "sad/sad-entry/"
			    "ipsec-sa-config/seq-overflow", "%s: seq-overflow "
			    "must be false with AEAD (RFC 9061)", name));
		if (in != NULL && in->key != NULL)
			return (fault(ie, EINVAL, "sad/sad-entry/"
			    "ipsec-sa-config/esp-sa/integrity/key", "%s: AEAD "
			    "takes no integrity key", name));
	} else {
		if (in == NULL || in->key == NULL)
			return (fault(ie, EINVAL, "sad/sad-entry/"
			    "ipsec-sa-config/esp-sa/integrity/key", "%s: AES-CBC "
			    "needs integrity: no integrity key", name));
		aalg = in->has_integrity_algorithm ? in->integrity_algorithm :
		    12;
		for (j = 0; j < nitems(ints) && ints[j].iana != aalg; j++)
			;
		if (j == nitems(ints))
			return (fault(ie, EOPNOTSUPP, "sad/sad-entry/"
			    "ipsec-sa-config/esp-sa/integrity/"
			    "integrity-algorithm", "%s: integrity %u: taken are "
			    "2 (HMAC-SHA1-96), 12, 13 and 14 (HMAC-SHA2-256, "
			    "-384, -512)", name, aalg));
		if ((n = hex_of(in->key, k->ak, sizeof(k->ak))) <= 0 ||
		    (size_t)n != ints[j].keylen[0])
			return (fault(ie, EINVAL, "sad/sad-entry/"
			    "ipsec-sa-config/esp-sa/integrity/key", "%s: an "
			    "integrity key of %zu bytes is wanted", name,
			    ints[j].keylen[0]));
		k->sa.aalg = ints[j].alg;
		k->sa.akeylen = (size_t)n;
	}
	/* ESP in UDP. */
	ec = c->encapsulation_type;
	if (ec != NULL && ec->has_espencap && ec->espencap == ENCAP_TCP)
		return (fault(ie, EOPNOTSUPP, "sad/sad-entry/ipsec-sa-config/"
		    "encapsulation-type/espencap", "%s: espintcp: FreeBSD has "
		    "no ESP in TCP", name));
	if (ec != NULL && ec->has_espencap && ec->espencap == ENCAP_UDP) {
		if (ec->oaddr.n > 0)
			return (fault(ie, EOPNOTSUPP, "sad/sad-entry/"
			    "ipsec-sa-config/encapsulation-type/oaddr", "%s: "
			    "original addresses are not taken: the SA's own "
			    "are given as NAT-T's", name));
		k->sa.natt = true;
		k->sa.sport = ec->has_sport ? ec->sport : 4500;
		k->sa.dport = ec->has_dport ? ec->dport : 4500;
	}
	return (lifetime_of(k, c->sa_lifetime_soft, c->sa_lifetime_hard, ie,
	    name));
}

/* An spd-entry as the kernel is to have it, the i-th of the list. */
static int
sp_compile(const ysp *e, size_t i, struct ikl_sp *k, struct iklerr *ie)
{
	const yspcfg	*c = e->ipsec_policy_config;
	const ytsel	*ts;
	const yproc	*pi;
	const ysacfg2	*sc;
	const ysptun	*tu;
	uint16_t	 lport, rport;
	const char	*name = e->name;

	memset(k, 0, sizeof(*k));
	k->name = name;
	if (strlen(name) >= IKL_NAME || name[0] == '\0')
		return (fault(ie, EINVAL, "spd/spd-entry/name", "spd-entry "
		    "\"%.40s\": a name of 1 to %d characters", name,
		    IKL_NAME - 1));
	if (name_kernels(name))
		return (fault(ie, EINVAL, "spd/spd-entry/name", "%s: esp/ and "
		    "spd/ name the kernel's own entries", name));
	if (!e->has_direction)
		return (fault(ie, EINVAL, "spd/spd-entry/direction", "%s: no "
		    "direction", name));
	k->sp.dir = e->direction == SP_INBOUND ? IPSEC_DIR_INBOUND :
	    IPSEC_DIR_OUTBOUND;
	if (e->has_reqid && e->reqid > IPSEC_MANUAL_REQID_MAX)
		return (fault(ie, EINVAL, "spd/spd-entry/reqid", "%s: reqid "
		    "%ju: a manual one is 1 to %d", name, (uintmax_t)e->reqid,
		    IPSEC_MANUAL_REQID_MAX));
	k->sp.scope = IPSEC_POLICYSCOPE_GLOBAL;
	k->sp.priority = IKL_SP_BASE + (uint32_t)i;
	ts = c != NULL ? c->traffic_selector : NULL;
	if (ts == NULL || !ts->has_local_prefix || !ts->has_remote_prefix ||
	    !prefix_of(ts->local_prefix.v.m0, &k->sp.src, &k->sp.splen) ||
	    !prefix_of(ts->remote_prefix.v.m0, &k->sp.dst, &k->sp.dplen))
		return (fault(ie, EINVAL, "spd/spd-entry/ipsec-policy-config/"
		    "traffic-selector", "%s: the selector's local and remote "
		    "prefixes are wanted", name));
	if (k->sp.src.ss_family != k->sp.dst.ss_family)
		return (fault(ie, EINVAL, "spd/spd-entry/ipsec-policy-config/"
		    "traffic-selector", "%s: its prefixes are of two families",
		    name));
	k->sp.proto = !ts->has_inner_protocol || ts->inner_protocol.which ==
	    1 ? IPSEC_ULPROTO_ANY : ts->inner_protocol.v.m0;
	if (ports_of(ts->local_ports.n, ts->local_ports.v, &lport, ie,
	    "spd/spd-entry/ipsec-policy-config/traffic-selector/local-ports",
	    name, "local") != 0 || ports_of(ts->remote_ports.n,
	    (const yports *)ts->remote_ports.v, &rport, ie,
	    "spd/spd-entry/ipsec-policy-config/traffic-selector/remote-ports",
	    name, "remote") != 0)
		return (-1);
	if ((lport != 0 || rport != 0) && k->sp.proto == IPSEC_ULPROTO_ANY)
		return (fault(ie, EINVAL, "spd/spd-entry/ipsec-policy-config/"
		    "traffic-selector/inner-protocol", "%s: ports need a "
		    "protocol", name));
	port_set(&k->sp.src, lport);
	port_set(&k->sp.dst, rport);
	pi = c->processing_info;
	switch (pi != NULL && pi->has_action ? pi->action : SP_DISCARD) {
	case SP_BYPASS:
		k->sp.type = IPSEC_POLICY_NONE;
		return (0);
	case SP_DISCARD:
		k->sp.type = IPSEC_POLICY_DISCARD;
		return (0);
	}
	k->sp.type = IPSEC_POLICY_IPSEC;
	k->sp.nreq = 1;
	k->sp.rproto = IPPROTO_ESP;
	k->sp.reqid = e->has_reqid ? (uint16_t)e->reqid : 0;
	k->sp.level = k->sp.reqid != 0 ? IPSEC_LEVEL_UNIQUE :
	    IPSEC_LEVEL_REQUIRE;
	sc = pi->ipsec_sa_cfg;
	if (sc != NULL && sc->has_pfp_flag && sc->pfp_flag)
		return (fault(ie, EOPNOTSUPP, "spd/spd-entry/ipsec-policy-config/"
		    "processing-info/ipsec-sa-cfg/pfp-flag", "%s: pfp-flag: "
		    "FreeBSD's SAs are not made from the packet", name));
	if (sc == NULL || !sc->has_mode || sc->mode == SP_MODE_TRANSPORT) {
		k->sp.mode = IPSEC_MODE_TRANSPORT;
		return (0);
	}
	k->sp.mode = IPSEC_MODE_TUNNEL;
	tu = sc->tunnel;
	if (tu == NULL || !tu->has_local || !tu->has_remote ||
	    !addr_of(tu->local.v.m0, &k->sp.tsrc) ||
	    !addr_of(tu->remote.v.m0, &k->sp.tdst) ||
	    k->sp.tsrc.ss_family != k->sp.tdst.ss_family)
		return (fault(ie, EINVAL, "spd/spd-entry/ipsec-policy-config/"
		    "processing-info/ipsec-sa-cfg/tunnel", "%s: tunnel mode "
		    "needs the tunnel's local and remote addresses, of one "
		    "family", name));
	if (tu->has_df_bit && tu->df_bit != SP_DF_CLEAR)
		return (fault(ie, EOPNOTSUPP, "spd/spd-entry/ipsec-policy-config/"
		    "processing-info/ipsec-sa-cfg/tunnel/df-bit", "%s: df-bit: "
		    "FreeBSD sets it for all SAs at once (net.inet.ipsec.dfbit)",
		    name));
	if ((tu->has_bypass_dscp && !tu->bypass_dscp) || tu->dscp_mapping.n > 0)
		return (fault(ie, EOPNOTSUPP, "spd/spd-entry/ipsec-policy-config/"
		    "processing-info/ipsec-sa-cfg/tunnel/dscp-mapping", "%s: "
		    "DSCP mappings: FreeBSD's IPsec has none", name));
	return (0);
}

/* Whether two policies are of one selector and direction, which the
 * kernel holds one policy of (key_getsp()). */
static bool
sp_sel_same(const struct pfkey_sp *a, const struct pfkey_sp *b)
{

	return (a->dir == b->dir && a->proto == b->proto && a->splen ==
	    b->splen && a->dplen == b->dplen && addr_same(&a->src, &b->src) &&
	    addr_same(&a->dst, &b->dst) && port_get(&a->src) ==
	    port_get(&b->src) && port_get(&a->dst) == port_get(&b->dst));
}

/* Whether the kernel's policy k is the one compiled, all of it. */
static bool
sp_same(const struct pfkey_sp *k, const struct pfkey_sp *c)
{

	if (!sp_sel_same(k, c) || k->scope != IPSEC_POLICYSCOPE_GLOBAL ||
	    k->priority != c->priority || k->type != c->type)
		return (false);
	if (c->type != IPSEC_POLICY_IPSEC)
		return (true);
	return (k->nreq == 1 && k->rproto == c->rproto && k->mode == c->mode &&
	    k->level == c->level && k->reqid == c->reqid &&
	    (c->mode != IPSEC_MODE_TUNNEL || (addr_same(&k->tsrc, &c->tsrc) &&
	    addr_same(&k->tdst, &c->tdst))));
}

/* Whether two compiled SAs are one, keys and the agent's lifetimes too. */
static bool
sa_same(const struct ikl_sa *a, const struct ikl_sa *b)
{
	const struct pfkey_sa	*x = &a->sa, *y = &b->sa;

	return (x->spi == y->spi && addr_same(&x->src, &y->src) && addr_same(&x->dst, &y->dst) &&
	    x->reqid == y->reqid && x->mode == y->mode && x->replay ==
	    y->replay && x->flags == y->flags && x->ealg == y->ealg &&
	    x->aalg == y->aalg && x->ekeylen == y->ekeylen && x->akeylen ==
	    y->akeylen && memcmp(a->ek, b->ek, x->ekeylen) == 0 &&
	    memcmp(a->ak, b->ak, x->akeylen) == 0 && x->natt == y->natt &&
	    x->sport == y->sport && x->dport == y->dport && x->lifetimes ==
	    y->lifetimes && memcmp(&x->soft, &y->soft, sizeof(x->soft)) == 0 &&
	    memcmp(&x->hard, &y->hard, sizeof(x->hard)) == 0 &&
	    a->idle_soft == b->idle_soft && a->idle_hard == b->idle_hard);
}

static void
set_free(struct ikl_set *s)
{

	if (s->sa != NULL)
		OPENSSL_cleanse(s->sa, s->nsa * sizeof(*s->sa));
	free(s->sa);
	free(s->sp);
	memset(s, 0, sizeof(*s));
}

/* A configuration's entries compiled, or why not. */
static int
set_compile(const yikl *c, struct ikl_set *s, struct iklerr *ie)
{
	const ysad	*sad = c != NULL ? c->sad : NULL;
	const yspd	*spd = c != NULL ? c->spd : NULL;
	size_t		 nsa, nsp, i, j;

	memset(s, 0, sizeof(*s));
	nsa = sad != NULL ? sad->sad_entry.n : 0;
	nsp = spd != NULL ? spd->spd_entry.n : 0;
	if (nsa > IKL_MAX || nsp > IKL_MAX)
		return (fault(ie, EINVAL, nsa > IKL_MAX ? "sad" : "spd", "more "
		    "than %d entries", IKL_MAX));
	if ((s->sa = calloc(nsa + 1, sizeof(*s->sa))) == NULL ||
	    (s->sp = calloc(nsp + 1, sizeof(*s->sp))) == NULL) {
		set_free(s);
		return (fault(ie, ENOMEM, NULL, "out of memory"));
	}
	for (i = 0; i < nsa; i++, s->nsa++) {
		if (sa_compile(&sad->sad_entry.v[i], &s->sa[i], ie) != 0)
			goto bad;
		for (j = 0; j < i; j++)
			if (s->sa[j].sa.spi == s->sa[i].sa.spi &&
			    addr_same(&s->sa[j].sa.dst, &s->sa[i].sa.dst)) {
				fault(ie, EINVAL, "sad/sad-entry/ipsec-sa-config/"
				    "spi", "%s and %s: one SA, the same SPI to "
				    "the same destination", s->sa[j].name,
				    s->sa[i].name);
				goto bad;
			}
	}
	for (i = 0; i < nsp; i++, s->nsp++) {
		if (sp_compile(&spd->spd_entry.v[i], i, &s->sp[i], ie) != 0)
			goto bad;
		for (j = 0; j < i; j++)
			if (sp_sel_same(&s->sp[j].sp, &s->sp[i].sp)) {
				fault(ie, EINVAL, "spd/spd-entry/"
				    "ipsec-policy-config/traffic-selector", "%s "
				    "and %s: one selector and direction, which "
				    "the kernel holds one policy of",
				    s->sp[j].name, s->sp[i].name);
				goto bad;
			}
	}
	return (0);
bad:
	set_free(s);
	return (-1);
}

/* ---- Running, kept ----------------------------------------------------- */

static int
kept_read(struct ietf_i2nsf_ikeless *data, cbl_yarena *a)
{
	struct stat	 sb;
	char		 path[MAXPATHLEN], why[160];
	uint8_t		*p;
	ssize_t		 n;
	int		 fd, error;

	sdwan_conf_path(IKL_FILE, path, sizeof(path));
	if ((fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)) == -1)
		return (errno == ENOENT ? 0 : errno);
	if (fstat(fd, &sb) != 0 || !S_ISREG(sb.st_mode) || sb.st_size <= 0 ||
	    sb.st_size > IKL_FILE_MAX || (p = malloc((size_t)sb.st_size)) ==
	    NULL) {
		close(fd);
		logmsg(LOG_ERR, "%s: cannot be read", path);
		return (EIO);
	}
	n = read(fd, p, (size_t)sb.st_size);
	close(fd);
	if (n != sb.st_size) {
		OPENSSL_cleanse(p, (size_t)sb.st_size);
		free(p);
		return (EIO);
	}
	error = cbl_ydecode_member(ikl_node(), p, (size_t)n, data, a,
	    CBL_YD_STRICT, why, sizeof(why));
	OPENSSL_cleanse(p, (size_t)n);
	free(p);
	if (error != 0)
		logmsg(LOG_ERR, "%s: %s", path, why);
	return (error);
}

static int
kept_write(const struct ietf_i2nsf_ikeless *data, char *err, size_t errlen)
{
	struct cbl_ybuf	 b = { NULL, 0, 0 };
	char		 path[MAXPATHLEN], tmp[MAXPATHLEN];
	int		 error, fd;

	sdwan_conf_path(IKL_FILE, path, sizeof(path));
	if (data == NULL || data->ipsec_ikeless == NULL) {
		if (unlink(path) == -1 && errno != ENOENT) {
			snprintf(err, errlen, "%s: %s", path, strerror(errno));
			return (-1);
		}
		return (0);
	}
	if ((error = cbl_yencode_member(ikl_node(), data, &b)) != 0) {
		snprintf(err, errlen, "%s", strerror(error));
		return (-1);
	}
	snprintf(tmp, sizeof(tmp), "%s.new", path);
	error = 0;
	if ((fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC |
	    O_NOFOLLOW, 0600)) == -1)
		error = errno;
	else {
		if (write(fd, b.p, b.len) != (ssize_t)b.len || fsync(fd) != 0)
			error = errno != 0 ? errno : EIO;
		if (close(fd) != 0 && error == 0)
			error = errno;
		if (error == 0 && rename(tmp, path) != 0)
			error = errno;
		if (error != 0)
			(void)unlink(tmp);
	}
	OPENSSL_cleanse(b.p, b.len);
	cbl_ybuf_free(&b);
	if (error != 0) {
		snprintf(err, errlen, "%s: %s", path, strerror(error));
		return (-1);
	}
	return (0);
}

/* ---- What the news and the counters need ----------------------------- */

/* Running's entries made those the news name and the counters watch,
 * what was watched of an SA still there kept. */
static void
live_set(const struct ikl_set *s)
{
	struct ikl_live	*nl;
	struct ikl_sp	*np;
	size_t		 i, j;

	nl = calloc(s->nsa + 1, sizeof(*nl));
	np = calloc(s->nsp + 1, sizeof(*np));
	if (nl == NULL || np == NULL) {
		free(nl);
		free(np);
		return;
	}
	pthread_mutex_lock(&live_lock);
	for (i = 0; i < s->nsa; i++) {
		nl[i].name = strdup(s->sa[i].name);
		nl[i].dst = s->sa[i].sa.dst;
		nl[i].spi = s->sa[i].sa.spi;
		nl[i].idle_soft = s->sa[i].idle_soft;
		nl[i].idle_hard = s->sa[i].idle_hard;
		for (j = 0; j < nlive_sa; j++)
			if (live_sa[j].spi == nl[i].spi &&
			    addr_same(&live_sa[j].dst, &nl[i].dst)) {
				nl[i].bytes = live_sa[j].bytes;
				nl[i].moved = live_sa[j].moved;
				nl[i].told_soft = live_sa[j].told_soft;
			}
	}
	for (i = 0; i < s->nsp; i++) {
		np[i] = s->sp[i];
		np[i].name = strdup(s->sp[i].name);
	}
	for (j = 0; j < nlive_sa; j++)
		free(live_sa[j].name);
	for (j = 0; j < nlive_sp; j++)
		free((char *)(uintptr_t)live_sp[j].name);
	free(live_sa);
	free(live_sp);
	live_sa = nl;
	nlive_sa = s->nsa;
	live_sp = np;
	nlive_sp = s->nsp;
	pthread_mutex_unlock(&live_lock);
}

/* The controller's name of the SA of spi to dst into buf; false: not
 * one of its own. */
bool
ikeless_sa_name(const struct sockaddr_storage *dst, uint32_t spi, char *buf,
    size_t len)
{
	bool	found = false;

	pthread_mutex_lock(&live_lock);
	for (size_t i = 0; i < nlive_sa && !found; i++)
		if (live_sa[i].spi == spi && addr_same(&live_sa[i].dst, dst)) {
			if (buf != NULL && live_sa[i].name != NULL)
				(void)strlcpy(buf, live_sa[i].name, len);
			found = true;
		}
	pthread_mutex_unlock(&live_lock);
	return (found);
}

/* The controller's name of the kernel's policy sp; false: not its own. */
bool
ikeless_sp_name(const struct pfkey_sp *sp, char *buf, size_t len)
{
	bool	found = false;

	if (sp->scope != IPSEC_POLICYSCOPE_GLOBAL || sp->priority <
	    IKL_SP_BASE || sp->priority >= IKL_SP_BASE + IKL_MAX)
		return (false);
	pthread_mutex_lock(&live_lock);
	for (size_t i = 0; i < nlive_sp && !found; i++)
		if (sp_sel_same(&live_sp[i].sp, sp)) {
			if (live_sp[i].name != NULL)
				(void)strlcpy(buf, live_sp[i].name, len);
			found = true;
		}
	pthread_mutex_unlock(&live_lock);
	return (found);
}

/*
 * One SA as the counters read it (sadb.c, every SADB_CHECK seconds):
 * of the controller's, its lifetimes the kernel does not enforce,
 * packets and idle.  Soft reached: told once (sadb-expire, soft); hard:
 * taken out (SADB_DELETE) and told.
 */
void
ikeless_lifetimes(struct work *w, int fd, const struct pfkey_sa *sa)
{
	struct ietf_i2nsf_ikeless_sadb_expire			 n;
	struct ietf_i2nsf_ikeless_sadb_expire_lifetime_current	 lc;
	char		 name[IKL_NAME];
	const char	*e;
	time_t		 now = time(NULL);
	uint32_t	 idle;
	size_t		 i;
	bool		 soft = false, hard = false;

	pthread_mutex_lock(&live_lock);
	for (i = 0; i < nlive_sa; i++)
		if (live_sa[i].spi == sa->spi && addr_same(&live_sa[i].dst,
		    &sa->dst))
			break;
	if (i == nlive_sa) {
		pthread_mutex_unlock(&live_lock);
		return;
	}
	if (live_sa[i].moved == 0 || sa->bytes != live_sa[i].bytes) {
		live_sa[i].bytes = sa->bytes;
		live_sa[i].moved = now;
	}
	idle = (uint32_t)(now - live_sa[i].moved);
	if ((sa->hard.packets != 0 && sa->packets >= sa->hard.packets) ||
	    (live_sa[i].idle_hard != 0 && idle >= live_sa[i].idle_hard))
		hard = true;
	else if (!live_sa[i].told_soft && ((sa->soft.packets != 0 &&
	    sa->packets >= sa->soft.packets) || (live_sa[i].idle_soft != 0 &&
	    idle >= live_sa[i].idle_soft))) {
		soft = true;
		live_sa[i].told_soft = true;
	}
	(void)strlcpy(name, live_sa[i].name != NULL ? live_sa[i].name : "",
	    sizeof(name));
	pthread_mutex_unlock(&live_lock);
	if (!soft && !hard)
		return;
	if (hard && pfkey_delete(w, fd, (const struct sockaddr *)&sa->src,
	    (const struct sockaddr *)&sa->dst, sa->spi, &e) == -1 &&
	    errno != ESRCH) {
		logmsg(LOG_WARNING, "IPsec SA %s: its hard lifetime is reached "
		    "but it could not be taken out: %s", name, e);
		return;
	}
	memset(&n, 0, sizeof(n));
	memset(&lc, 0, sizeof(lc));
	n.ipsec_sa_name = name;
	n.has_soft_lifetime_expire = true;
	n.soft_lifetime_expire = !hard;
	if (sa->added != 0 && (uint64_t)now >= sa->added) {
		lc.has_time = true;
		lc.time = (uint32_t)((uint64_t)now - sa->added);
	}
	lc.has_bytes = lc.has_packets = lc.has_idle = true;
	lc.bytes = sa->bytes;
	lc.packets = sa->packets;
	lc.idle = idle;
	n.lifetime_current = &lc;
	yang_sadb_expire(&n);
}

/* ---- The kernel's ---------------------------------------------------- */

struct kstate {
	struct pfkey_sa	*sa;
	size_t		 nsa, cap_sa;
	struct pfkey_sp	*sp;
	size_t		 nsp, cap_sp;
	bool		 nomem;
};

static void
ks_sa(const struct pfkey_sa *sa, void *arg)
{
	struct kstate	*k = arg;
	struct pfkey_sa	*v;

	if (k->nsa == k->cap_sa) {
		if ((v = reallocarray(k->sa, k->cap_sa * 2 + 16,
		    sizeof(*v))) == NULL) {
			k->nomem = true;
			return;
		}
		k->sa = v;
		k->cap_sa = k->cap_sa * 2 + 16;
	}
	k->sa[k->nsa++] = *sa;
}

static void
ks_sp(const struct pfkey_sp *sp, void *arg)
{
	struct kstate	*k = arg;
	struct pfkey_sp	*v;

	if (k->nsp == k->cap_sp) {
		if ((v = reallocarray(k->sp, k->cap_sp * 2 + 16,
		    sizeof(*v))) == NULL) {
			k->nomem = true;
			return;
		}
		k->sp = v;
		k->cap_sp = k->cap_sp * 2 + 16;
	}
	k->sp[k->nsp++] = *sp;
}

static void
ks_free(struct kstate *k)
{

	free(k->sa);
	free(k->sp);
	memset(k, 0, sizeof(*k));
}

/* The SAD and SPD of the host's network; -1 and why. */
static int
ks_read(struct work *w, int fd, struct kstate *k, const char **errp)
{

	memset(k, 0, sizeof(*k));
	if (pfkey_dump(w, fd, ks_sa, k, errp) == -1 ||
	    pfkey_spddump(w, fd, ks_sp, k, errp) == -1) {
		ks_free(k);
		return (-1);
	}
	if (k->nomem) {
		ks_free(k);
		*errp = "out of memory";
		return (-1);
	}
	return (0);
}

static const struct pfkey_sa *
ks_find_sa(const struct kstate *k, const struct pfkey_sa *sa)
{

	for (size_t i = 0; i < k->nsa; i++)
		if (k->sa[i].spi == sa->spi && addr_same(&k->sa[i].dst,
		    &sa->dst))
			return (&k->sa[i]);
	return (NULL);
}

static const struct pfkey_sp *
ks_find_sp(const struct kstate *k, const struct pfkey_sp *sp)
{

	for (size_t i = 0; i < k->nsp; i++)
		if (k->sp[i].scope == IPSEC_POLICYSCOPE_GLOBAL &&
		    sp_sel_same(&k->sp[i], sp))
			return (&k->sp[i]);
	return (NULL);
}

static bool
sp_ours(const struct pfkey_sp *k)
{

	return (k->scope == IPSEC_POLICYSCOPE_GLOBAL && k->priority >=
	    IKL_SP_BASE && k->priority < IKL_SP_BASE + IKL_MAX);
}

/* ---- Applied --------------------------------------------------------- */

/* A step done, so that it can be undone. */
struct ikl_step {
	enum { SA_ADDED, SA_DELETED, SP_ADDED, SP_DELETED, SP_UPDATED } what;
	const struct ikl_sa	*sa;		/* added or deleted */
	struct pfkey_sp		 sp, old;	/* added; updated from old */
};

struct journal {
	struct ikl_step	*v;
	size_t		 n;
};

static bool	preferred_said;

/* The newest SA used outbound (RFC 9061 Appendix D.2's rekey): the
 * kernel's choice between two of one pair, the host's own. */
static void
preferred_newsa(void)
{
	int	zero = 0, cur;
	size_t	len = sizeof(cur);

	if (opts.pfkey_path != NULL)
		return;
	if (sysctlbyname("net.key.preferred_oldsa", &cur, &len, NULL, 0) ==
	    0 && cur == 0)
		return;
	if (sysctlbyname("net.key.preferred_oldsa", NULL, NULL, &zero,
	    sizeof(zero)) != 0) {
		if (!preferred_said)
			logmsg(LOG_WARNING, "net.key.preferred_oldsa could not "
			    "be set to 0: %s", strerror(errno));
		preferred_said = true;
		return;
	}
	logmsg(LOG_NOTICE, "net.key.preferred_oldsa set to 0: the newest SA "
	    "of a pair carries the traffic (RFC 9061 Appendix D.2)");
}


/* An SA put in, then read back (SADB_GET) as it was given, mature. */
static int
sa_put(struct work *w, int fd, const struct ikl_sa *k, const char **errp)
{
	struct pfkey_sa	 sa, got;
	const char	*bad;
	int		 rc;

	sa = k->sa;
	sa.ekey = k->ek;
	sa.akey = k->sa.akeylen > 0 ? k->ak : NULL;
	rc = pfkey_add(w, fd, &sa, errp);
	OPENSSL_cleanse(&sa, sizeof(sa));
	if (rc == -1 || pfkey_get(w, fd, (const struct sockaddr *)&k->sa.src,
	    (const struct sockaddr *)&k->sa.dst, k->sa.spi, &got, errp) == -1)
		return (-1);
	bad = got.spi != k->sa.spi ? "another SPI" : got.state !=
	    SADB_SASTATE_MATURE ? "not mature" : got.reqid != k->sa.reqid ?
	    "another reqid" : got.mode != k->sa.mode ? "another mode" :
	    got.replay != k->sa.replay ? "another replay window" :
	    (got.flags & SADB_X_SAFLAGS_ESN) != (k->sa.flags &
	    SADB_X_SAFLAGS_ESN) ? "ESN otherwise" : got.ealg != k->sa.ealg ||
	    (!k->aead && got.aalg != k->sa.aalg) ? "other algorithms" :
	    got.natt != k->sa.natt ? "ESP in UDP otherwise" :
	    (got.lifetimes & (PFKEY_LT_SOFT | PFKEY_LT_HARD)) !=
	    k->sa.lifetimes || (k->sa.lifetimes != 0 && (got.soft.time !=
	    k->sa.soft.time || got.soft.bytes != k->sa.soft.bytes ||
	    got.hard.time != k->sa.hard.time || got.hard.bytes !=
	    k->sa.hard.bytes)) ? "other lifetimes" : NULL;
	if (bad != NULL) {
		*errp = wfmt(w, "the kernel has it with %s", bad);
		errno = EIO;
		return (-1);
	}
	return (0);
}

static void
journal_add(struct journal *j, const struct ikl_step *s)
{
	struct ikl_step	*v;

	/* Room was made for every step before the first. */
	v = j->v;
	v[j->n++] = *s;
}

/* What the journal did undone, last first; false when a step could not
 * be, why in *errp. */
static bool
undo(struct work *w, int fd, struct journal *j, const char **errp)
{
	const struct ikl_step	*s;
	struct pfkey_sp		 sp;
	const char		*e = NULL;
	bool			 ok = true;

	while (j->n > 0) {
		s = &j->v[--j->n];
		sp = s->old;
		switch (s->what) {
		case SP_ADDED:
			if (pfkey_spddelete(w, fd, s->sp.id, &e) == -1)
				ok = false;
			break;
		case SP_UPDATED:
			if (pfkey_spdupdate(w, fd, &sp, &e) == -1)
				ok = false;
			break;
		case SP_DELETED:
			if (pfkey_spdadd(w, fd, &sp, &e) == -1)
				ok = false;
			break;
		case SA_ADDED:
			if (pfkey_delete(w, fd, (const struct sockaddr *)
			    &s->sa->sa.src, (const struct sockaddr *)
			    &s->sa->sa.dst, s->sa->sa.spi, &e) == -1 &&
			    errno != ESRCH)
				ok = false;
			break;
		case SA_DELETED:
			if (sa_put(w, fd, s->sa, &e) == -1)
				ok = false;
			break;
		}
		if (!ok && *errp == NULL)
			*errp = e;
	}
	return (ok);
}

static const struct ikl_sa *
set_sa(const struct ikl_set *s, const char *name)
{

	for (size_t i = 0; i < s->nsa; i++)
		if (strcmp(s->sa[i].name, name) == 0)
			return (&s->sa[i]);
	return (NULL);
}

static const struct ikl_sp *
set_sp(const struct ikl_set *s, const char *name)
{

	for (size_t i = 0; i < s->nsp; i++)
		if (strcmp(s->sp[i].name, name) == 0)
			return (&s->sp[i]);
	return (NULL);
}

/*
 * The kernel moved from running's entries (b) to the new ones (n): what
 * differs alone, policies out, SAs out, SAs in, policies in (updated in
 * place where one of the controller's has the selector).  An entry that
 * would take one not the controller's is refused before anything is
 * done; a step refused undoes those before it.  0, or -1 and why.
 */
static int
apply(struct work *w, int fd, const struct ikl_set *b, const struct ikl_set *n,
    struct iklerr *ie, size_t *nadd, size_t *ndel)
{
	struct kstate		 k;
	struct journal		 j;
	struct ikl_step		 st;
	const struct ikl_sa	*o;
	const struct ikl_sp	*op;
	const struct pfkey_sa	*ksa;
	const struct pfkey_sp	*ksp;
	struct pfkey_sp		 sp;
	const char		*e = NULL, *ue = NULL;
	size_t			 i, m;
	bool			*sa_new, *sp_new, *sa_gone, *sp_gone;
	int			 rc = -1;

	*nadd = *ndel = 0;
	if (ks_read(w, fd, &k, &e) == -1)
		return (fault(ie, EIO, NULL, "PF_KEY: the SAD and SPD could not "
		    "be read: %s", e));
	sa_new = calloc(n->nsa + 1, sizeof(bool));
	sp_new = calloc(n->nsp + 1, sizeof(bool));
	sa_gone = calloc(b->nsa + 1, sizeof(bool));
	sp_gone = calloc(b->nsp + 1, sizeof(bool));
	j.n = 0;
	j.v = calloc(2 * (n->nsa + n->nsp + b->nsa + b->nsp) + 1,
	    sizeof(*j.v));
	if (sa_new == NULL || sp_new == NULL || sa_gone == NULL ||
	    sp_gone == NULL || j.v == NULL) {
		fault(ie, ENOMEM, NULL, "out of memory");
		goto out;
	}
	/* What differs. */
	for (i = 0; i < b->nsa; i++)
		sa_gone[i] = (o = set_sa(n, b->sa[i].name)) == NULL ||
		    !sa_same(o, &b->sa[i]);
	for (i = 0; i < n->nsa; i++)
		sa_new[i] = (o = set_sa(b, n->sa[i].name)) == NULL ||
		    !sa_same(o, &n->sa[i]);
	for (i = 0; i < b->nsp; i++)
		sp_gone[i] = (op = set_sp(n, b->sp[i].name)) == NULL ||
		    !sp_same(&op->sp, &b->sp[i].sp);
	for (i = 0; i < n->nsp; i++)
		sp_new[i] = (op = set_sp(b, n->sp[i].name)) == NULL ||
		    !sp_same(&op->sp, &n->sp[i].sp);
	/* Whose what is taken is: the controller's alone. */
	for (i = 0; i < n->nsa; i++) {
		if (!sa_new[i] || (ksa = ks_find_sa(&k, &n->sa[i].sa)) == NULL)
			continue;
		for (m = 0; m < b->nsa; m++)
			if (sa_gone[m] && b->sa[m].sa.spi == ksa->spi &&
			    addr_same(&b->sa[m].sa.dst, &ksa->dst))
				break;
		if (m == b->nsa) {
			char	a[INET6_ADDRSTRLEN];

			addr_text(&ksa->dst, a, sizeof(a));
			fault(ie, EBUSY, "sad/sad-entry/ipsec-sa-config/spi",
			    "%s: the SA of SPI %#x to %s is the kernel's "
			    "already and not the controller's (setkey's, an "
			    "IKE daemon's, an ipsec-sa job's): left as it is",
			    n->sa[i].name, ksa->spi, a);
			goto out;
		}
	}
	for (i = 0; i < n->nsp; i++) {
		if (!sp_new[i] || (ksp = ks_find_sp(&k, &n->sp[i].sp)) == NULL ||
		    sp_ours(ksp))
			continue;
		fault(ie, EBUSY, "spd/spd-entry/ipsec-policy-config/"
		    "traffic-selector", "%s: the kernel has a policy of its "
		    "selector and direction already, spd/%u, not the "
		    "controller's (setkey's, an IKE daemon's, an ipsec-sa "
		    "job's): left as it is", n->sp[i].name, ksp->id);
		goto out;
	}
	/* Policies out, but those another takes the place of. */
	for (i = 0; i < b->nsp; i++) {
		if (!sp_gone[i] || (ksp = ks_find_sp(&k, &b->sp[i].sp)) ==
		    NULL || !sp_ours(ksp))
			continue;
		for (m = 0; m < n->nsp; m++)
			if (sp_new[m] && sp_sel_same(&n->sp[m].sp, ksp))
				break;
		if (m < n->nsp)
			continue;
		if (pfkey_spddelete(w, fd, ksp->id, &e) == -1) {
			fault(ie, errno == 0 ? EIO : errno, "spd/spd-entry",
			    "%s: %s", b->sp[i].name, e);
			goto undo;
		}
		memset(&st, 0, sizeof(st));
		st.what = SP_DELETED;
		st.old = *ksp;
		journal_add(&j, &st);
		(*ndel)++;
	}
	/* SAs out. */
	for (i = 0; i < b->nsa; i++) {
		if (!sa_gone[i] || ks_find_sa(&k, &b->sa[i].sa) == NULL)
			continue;
		if (pfkey_delete(w, fd, (const struct sockaddr *)&b->sa[i].sa.src,
		    (const struct sockaddr *)&b->sa[i].sa.dst, b->sa[i].sa.spi,
		    &e) == -1) {
			if (errno == ESRCH)
				continue;
			fault(ie, errno == 0 ? EIO : errno, "sad/sad-entry",
			    "%s: %s", b->sa[i].name, e);
			goto undo;
		}
		memset(&st, 0, sizeof(st));
		st.what = SA_DELETED;
		st.sa = &b->sa[i];
		journal_add(&j, &st);
		(*ndel)++;
	}
	/* SAs in. */
	for (i = 0; i < n->nsa; i++) {
		if (!sa_new[i])
			continue;
		if (sa_put(w, fd, &n->sa[i], &e) == -1) {
			fault(ie, errno == EEXIST ? EBUSY : errno == EINVAL ?
			    EINVAL : EIO, "sad/sad-entry", "%s: %s",
			    n->sa[i].name, e);
			/* One read back otherwise is in: out with it too. */
			memset(&st, 0, sizeof(st));
			st.what = SA_ADDED;
			st.sa = &n->sa[i];
			if (ie->error == EIO)
				journal_add(&j, &st);
			goto undo;
		}
		memset(&st, 0, sizeof(st));
		st.what = SA_ADDED;
		st.sa = &n->sa[i];
		journal_add(&j, &st);
		(*nadd)++;
	}
	/* Policies in, or in place of the controller's of the selector. */
	for (i = 0; i < n->nsp; i++) {
		if (!sp_new[i])
			continue;
		sp = n->sp[i].sp;
		memset(&st, 0, sizeof(st));
		if ((ksp = ks_find_sp(&k, &sp)) != NULL && sp_ours(ksp)) {
			st.what = SP_UPDATED;
			st.old = *ksp;
			rc = pfkey_spdupdate(w, fd, &sp, &e);
		} else {
			st.what = SP_ADDED;
			rc = pfkey_spdadd(w, fd, &sp, &e);
		}
		if (rc == -1) {
			fault(ie, errno == EEXIST ? EBUSY : errno == EINVAL ?
			    EINVAL : EIO, "spd/spd-entry", "%s: %s",
			    n->sp[i].name, e);
			rc = -1;
			goto undo;
		}
		st.sp = sp;
		journal_add(&j, &st);
		(*nadd)++;
	}
	/* Read back: every policy of the new ones as it was given. */
	ks_free(&k);
	if (ks_read(w, fd, &k, &e) == -1) {
		fault(ie, EIO, NULL, "PF_KEY: the SPD could not be read back: "
		    "%s", e);
		rc = -1;
		goto undo;
	}
	for (i = 0; i < n->nsp; i++)
		if ((ksp = ks_find_sp(&k, &n->sp[i].sp)) == NULL ||
		    !sp_same(ksp, &n->sp[i].sp)) {
			fault(ie, EIO, "spd/spd-entry", "%s: read back, the "
			    "kernel has it %s", n->sp[i].name, ksp == NULL ?
			    "not" : "otherwise");
			rc = -1;
			goto undo;
		}
	if (*nadd > 0 && n->nsa > 0)
		preferred_newsa();
	rc = 0;
	goto out;
undo:
	rc = -1;
	if (!undo(w, fd, &j, &ue))
		snprintf(ie->msg + strlen(ie->msg), sizeof(ie->msg) -
		    strlen(ie->msg), "; what was done before could not all be "
		    "undone: %s", ue != NULL ? ue : "PF_KEY");
	else if (j.v != NULL)
		snprintf(ie->msg + strlen(ie->msg), sizeof(ie->msg) -
		    strlen(ie->msg), "; nothing changed");
out:
	ks_free(&k);
	free(sa_new);
	free(sp_new);
	free(sa_gone);
	free(sp_gone);
	free(j.v);
	return (rc);
}

/*
 * after's entries made the kernel's, then kept; refused, an errno, why
 * in err and the node at fault in *sid (0: the container), the kernel
 * and running as they were.
 */
int
ikeless_edit(const struct ietf_i2nsf_ikeless *after, char *err,
    size_t errlen, uint64_t *sid)
{
	struct ietf_i2nsf_ikeless	 kept;
	struct ikl_set			 b, n;
	struct iklerr			 ie;
	struct work			 w;
	cbl_yarena			*a;
	const char			*e = NULL;
	size_t				 nadd, ndel;
	int				 fd, rc = -1;

	memset(&ie, 0, sizeof(ie));
	memset(&b, 0, sizeof(b));
	memset(&n, 0, sizeof(n));
	*sid = 0;
	if ((a = cbl_yarena_new()) == NULL) {
		snprintf(err, errlen, "out of memory");
		return (ENOMEM);
	}
	work_init(&w);
	pthread_mutex_lock(&ikl_lock);
	memset(&kept, 0, sizeof(kept));
	if (kept_read(&kept, a) != 0 || set_compile(kept.ipsec_ikeless, &b,
	    &ie) != 0) {
		/* Running unreadable: what the kernel has of it is left. */
		logmsg(LOG_ERR, "ipsec-ikeless: running's entries could not "
		    "be read: %s", ie.msg);
		memset(&b, 0, sizeof(b));
		memset(&ie, 0, sizeof(ie));
	}
	if (set_compile(after != NULL ? after->ipsec_ikeless : NULL, &n,
	    &ie) != 0)
		goto out;
	if ((fd = pfkey_open(&w, &e)) == -1) {
		fault(&ie, EIO, NULL, "%s", e);
		goto out;
	}
	rc = apply(&w, fd, &b, &n, &ie, &nadd, &ndel);
	close(fd);
	if (rc != 0)
		goto out;
	if (kept_write(after, ie.msg, sizeof(ie.msg)) != 0) {
		ie.error = EIO;
		rc = -1;
		goto out;
	}
	live_set(&n);
	logmsg(LOG_NOTICE, "ipsec-ikeless: %zu SAs and %zu policies; %zu put "
	    "in, %zu taken out", n.nsa, n.nsp, nadd, ndel);
out:
	pthread_mutex_unlock(&ikl_lock);
	set_free(&b);
	set_free(&n);
	work_free(&w);
	cbl_yarena_free(a);
	snprintf(err, errlen, "%s", ie.msg);
	*sid = ie.sid;
	if (rc == 0)
		return (0);
	return (ie.error != 0 ? ie.error : EIO);
}

/* ---- Read ------------------------------------------------------------ */

static void *
aalloc(cbl_yarena *a, size_t len, bool *nomem)
{
	void	*p;

	if ((p = cbl_yarena_alloc(a, len)) == NULL) {
		*nomem = true;
		return (NULL);
	}
	memset(p, 0, len);
	return (p);
}

static const char *
astr(cbl_yarena *a, const char *s, bool *nomem)
{
	char	*p;

	if ((p = aalloc(a, strlen(s) + 1, nomem)) != NULL)
		memcpy(p, s, strlen(s) + 1);
	return (p);
}

/* A prefix of the kernel's as RFC 9061's ip-prefix (which: the family). */
static const char *
aprefix(cbl_yarena *a, const struct sockaddr_storage *ss, unsigned plen,
    unsigned *which, bool *nomem)
{
	char	b[INET6_ADDRSTRLEN], p[INET6_ADDRSTRLEN + 8];

	addr_text(ss, b, sizeof(b));
	snprintf(p, sizeof(p), "%s/%u", b, plen > addr_max(ss) ?
	    addr_max(ss) : plen);
	*which = ss->ss_family == AF_INET6 ? 1 : 0;
	return (astr(a, p, nomem));
}

static const char *
aaddr(cbl_yarena *a, const struct sockaddr_storage *ss, unsigned *which,
    bool *nomem)
{
	char	b[INET6_ADDRSTRLEN];

	addr_text(ss, b, sizeof(b));
	*which = ss->ss_family == AF_INET6 ? 1 : 0;
	return (astr(a, b, nomem));
}

/* What the kernel tells of an SA's state: its age and load, its window
 * and counter. */
static const ysastate *
sa_state(cbl_yarena *a, const struct pfkey_sa *sa, bool *nomem)
{
	ysastate	*st;
	ycur		*cur;
	yreplay		*rp;
	ywin		*wn;
	time_t		 now = time(NULL);

	st = aalloc(a, sizeof(*st), nomem);
	cur = aalloc(a, sizeof(*cur), nomem);
	rp = aalloc(a, sizeof(*rp), nomem);
	wn = aalloc(a, sizeof(*wn), nomem);
	if (*nomem)
		return (NULL);
	if (sa->added != 0 && (uint64_t)now >= sa->added) {
		cur->has_time = true;
		cur->time = (uint32_t)((uint64_t)now - sa->added);
	}
	cur->has_bytes = cur->has_packets = true;
	cur->bytes = sa->bytes;
	cur->packets = sa->packets;
	wn->has_w = true;
	wn->w = sa->replay * 8;
	rp->replay_window = wn;
	rp->has_seq_number_counter = true;
	rp->seq_number_counter = sa->seq;
	st->sa_lifetime_current = cur;
	st->replay_stats = rp;
	return (st);
}

/* An SA of the controller's: its entry as running has it, the keys
 * left out, and the kernel's state of it. */
static void
sa_ours(cbl_yarena *a, const ysa *e, const struct pfkey_sa *sa, ysa *out,
    bool *nomem)
{
	ysacfg	*c;
	yespsa	*es;
	yenc	*en;
	yint	*in;

	*out = *e;
	out->ipsec_sa_state = sa_state(a, sa, nomem);
	if (e->ipsec_sa_config == NULL || e->ipsec_sa_config->esp_sa == NULL)
		return;
	if ((c = aalloc(a, sizeof(*c), nomem)) == NULL || (es = aalloc(a,
	    sizeof(*es), nomem)) == NULL)
		return;
	*c = *e->ipsec_sa_config;
	*es = *c->esp_sa;
	if (es->encryption != NULL && (en = aalloc(a, sizeof(*en), nomem)) !=
	    NULL) {
		*en = *es->encryption;
		en->key = en->iv = NULL;
		es->encryption = en;
	}
	if (es->integrity != NULL && (in = aalloc(a, sizeof(*in), nomem)) !=
	    NULL) {
		*in = *es->integrity;
		in->key = NULL;
		es->integrity = in;
	}
	c->esp_sa = es;
	out->ipsec_sa_config = c;
}

/* An SA not the controller's, as the kernel tells it, its keys never. */
static void
sa_foreign(cbl_yarena *a, const struct pfkey_sa *sa, ysa *out, bool *nomem)
{
	ysacfg		*c;
	yespsa		*es;
	yenc		*en;
	yint		*in;
	ysats		*ts;
	ysatun		*tu;
	yencap		*ec;
	ysoft		*so;
	yhard		*ha;
	char		 d[INET6_ADDRSTRLEN], name[INET6_ADDRSTRLEN + 20];
	size_t		 i;

	addr_text(&sa->dst, d, sizeof(d));
	snprintf(name, sizeof(name), "esp/%s/0x%08x", d, sa->spi);
	memset(out, 0, sizeof(*out));
	out->name = astr(a, name, nomem);
	out->has_reqid = true;
	out->reqid = sa->reqid;
	if ((c = aalloc(a, sizeof(*c), nomem)) == NULL)
		return;
	c->has_spi = true;
	c->spi = sa->spi;
	c->has_ext_seq_num = c->has_seq_overflow = true;
	c->ext_seq_num = (sa->flags & SADB_X_SAFLAGS_ESN) != 0;
	c->seq_overflow = (sa->flags & SADB_X_EXT_CYCSEQ) != 0;
	c->has_anti_replay_window_size = true;
	c->anti_replay_window_size = sa->replay * 8;
	c->has_protocol_parameters = c->has_mode = true;
	if (sa->mode == IPSEC_MODE_TUNNEL) {
		c->mode = SA_MODE_TUNNEL;
		if ((tu = aalloc(a, sizeof(*tu), nomem)) != NULL) {
			tu->has_local = tu->has_remote = true;
			tu->local.v.m0 = aaddr(a, &sa->src, &tu->local.which,
			    nomem);
			tu->remote.v.m0 = aaddr(a, &sa->dst, &tu->remote.which,
			    nomem);
			c->tunnel = tu;
		}
	} else {
		c->mode = SA_MODE_TRANSPORT;
		if ((ts = aalloc(a, sizeof(*ts), nomem)) != NULL) {
			ts->has_local_prefix = ts->has_remote_prefix = true;
			ts->local_prefix.v.m0 = aprefix(a, &sa->src, 128,
			    &ts->local_prefix.which, nomem);
			ts->remote_prefix.v.m0 = aprefix(a, &sa->dst, 128,
			    &ts->remote_prefix.which, nomem);
			ts->has_inner_protocol = true;
			ts->inner_protocol.which = 1;
			ts->inner_protocol.v.m1 = SA_PROTO_ANY;
			c->traffic_selector = ts;
		}
	}
	if ((es = aalloc(a, sizeof(*es), nomem)) != NULL) {
		for (i = 0; i < nitems(kencs); i++)
			if (kencs[i].alg == sa->ealg &&
			    (en = aalloc(a, sizeof(*en), nomem)) != NULL) {
				en->has_encryption_algorithm = true;
				en->encryption_algorithm = kencs[i].iana;
				es->encryption = en;
			}
		for (i = 0; i < nitems(kints); i++)
			if (kints[i].alg == sa->aalg &&
			    (in = aalloc(a, sizeof(*in), nomem)) != NULL) {
				in->has_integrity_algorithm = true;
				in->integrity_algorithm = kints[i].iana;
				es->integrity = in;
			}
		c->esp_sa = es;
	}
	if ((sa->lifetimes & PFKEY_LT_SOFT) != 0 &&
	    (so = aalloc(a, sizeof(*so), nomem)) != NULL) {
		so->has_time = so->has_bytes = so->has_packets = true;
		so->time = (uint32_t)sa->soft.time;
		so->bytes = sa->soft.bytes;
		so->packets = sa->soft.packets;
		c->sa_lifetime_soft = so;
	}
	if ((sa->lifetimes & PFKEY_LT_HARD) != 0 &&
	    (ha = aalloc(a, sizeof(*ha), nomem)) != NULL) {
		ha->has_time = ha->has_bytes = ha->has_packets = true;
		ha->time = (uint32_t)sa->hard.time;
		ha->bytes = sa->hard.bytes;
		ha->packets = sa->hard.packets;
		c->sa_lifetime_hard = ha;
	}
	if (sa->natt && (ec = aalloc(a, sizeof(*ec), nomem)) != NULL) {
		ec->has_espencap = ec->has_sport = ec->has_dport = true;
		ec->espencap = ENCAP_UDP;
		ec->sport = sa->sport;
		ec->dport = sa->dport;
		c->encapsulation_type = ec;
	}
	out->ipsec_sa_config = c;
	out->ipsec_sa_state = sa_state(a, sa, nomem);
}

/* A policy not the controller's, as the kernel tells it; false: one
 * the model has no words for (fwd, entrust, AH, bundles). */
static bool
sp_foreign(cbl_yarena *a, const struct pfkey_sp *sp, ysp *out, bool *nomem)
{
	yspcfg		*c;
	ytsel		*ts;
	yproc		*pi;
	ysacfg2		*sc;
	ysptun		*tu;
	yports		*pv;
	char		 name[32];

	if ((sp->dir != IPSEC_DIR_INBOUND && sp->dir != IPSEC_DIR_OUTBOUND) ||
	    (sp->type != IPSEC_POLICY_IPSEC && sp->type != IPSEC_POLICY_NONE &&
	    sp->type != IPSEC_POLICY_DISCARD && sp->type !=
	    IPSEC_POLICY_BYPASS) || (sp->type == IPSEC_POLICY_IPSEC &&
	    (sp->nreq != 1 || sp->rproto != IPPROTO_ESP)))
		return (false);
	memset(out, 0, sizeof(*out));
	snprintf(name, sizeof(name), "spd/%u", sp->id);
	out->name = astr(a, name, nomem);
	out->has_direction = true;
	out->direction = sp->dir == IPSEC_DIR_INBOUND ? SP_INBOUND :
	    SP_OUTBOUND;
	out->has_reqid = true;
	out->reqid = sp->type == IPSEC_POLICY_IPSEC ? sp->reqid : 0;
	c = aalloc(a, sizeof(*c), nomem);
	ts = aalloc(a, sizeof(*ts), nomem);
	pi = aalloc(a, sizeof(*pi), nomem);
	if (*nomem)
		return (false);
	ts->has_local_prefix = ts->has_remote_prefix = true;
	ts->local_prefix.v.m0 = aprefix(a, &sp->src, sp->splen,
	    &ts->local_prefix.which, nomem);
	ts->remote_prefix.v.m0 = aprefix(a, &sp->dst, sp->dplen,
	    &ts->remote_prefix.which, nomem);
	ts->has_inner_protocol = true;
	if (sp->proto == IPSEC_ULPROTO_ANY) {
		ts->inner_protocol.which = 1;
		ts->inner_protocol.v.m1 = SP_PROTO_ANY;
	} else
		ts->inner_protocol.v.m0 = sp->proto;
	if (port_get(&sp->src) != 0 && (pv = aalloc(a, sizeof(*pv), nomem)) !=
	    NULL) {
		pv->start = pv->end = port_get(&sp->src);
		ts->local_ports.n = 1;
		ts->local_ports.v = pv;
	}
	if (port_get(&sp->dst) != 0 && (pv = aalloc(a, sizeof(*pv), nomem)) !=
	    NULL) {
		pv->start = pv->end = port_get(&sp->dst);
		ts->remote_ports.n = 1;
		ts->remote_ports.v = (const void *)pv;
	}
	pi->has_action = true;
	pi->action = sp->type == IPSEC_POLICY_IPSEC ? SP_PROTECT :
	    sp->type == IPSEC_POLICY_DISCARD ? SP_DISCARD : SP_BYPASS;
	if (sp->type == IPSEC_POLICY_IPSEC &&
	    (sc = aalloc(a, sizeof(*sc), nomem)) != NULL) {
		sc->has_mode = sc->has_protocol_parameters = true;
		sc->mode = sp->mode == IPSEC_MODE_TUNNEL ? SP_MODE_TUNNEL :
		    SP_MODE_TRANSPORT;
		if (sp->mode == IPSEC_MODE_TUNNEL &&
		    (tu = aalloc(a, sizeof(*tu), nomem)) != NULL) {
			tu->has_local = tu->has_remote = true;
			tu->local.v.m0 = aaddr(a, &sp->tsrc, &tu->local.which,
			    nomem);
			tu->remote.v.m0 = aaddr(a, &sp->tdst, &tu->remote.which,
			    nomem);
			sc->tunnel = tu;
		}
		pi->ipsec_sa_cfg = sc;
	}
	c->traffic_selector = ts;
	c->processing_info = pi;
	out->ipsec_policy_config = c;
	return (true);
}

/* The kernel's SAD and SPD as the lists, the controller's entries
 * by their names. */
static int
operational(cbl_yarena *a, const yikl *kept, const struct ikl_set *s,
    const yikl **out)
{
	struct kstate		 k;
	struct work		 w;
	yikl			*c;
	ysad			*sad;
	yspd			*spd;
	ysa			*sv;
	ysp			*pv;
	const char		*e = NULL;
	size_t			 i, m, ns, np;
	int			 fd;
	bool			 nomem = false;

	*out = NULL;
	work_init(&w);
	w.nice = true;
	if ((fd = pfkey_open(&w, &e)) == -1) {
		/* No PF_KEY (no ipsec.ko): no SAs, no policies. */
		work_free(&w);
		return (0);
	}
	if (ks_read(&w, fd, &k, &e) == -1) {
		close(fd);
		logmsg(LOG_INFO, "a read of ipsec-ikeless failed: %s", e);
		work_free(&w);
		return (EIO);
	}
	close(fd);
	c = aalloc(a, sizeof(*c), &nomem);
	sad = aalloc(a, sizeof(*sad), &nomem);
	spd = aalloc(a, sizeof(*spd), &nomem);
	sv = aalloc(a, (k.nsa + 1) * sizeof(*sv), &nomem);
	pv = aalloc(a, (k.nsp + 1) * sizeof(*pv), &nomem);
	for (i = ns = 0; !nomem && i < k.nsa; i++) {
		for (m = 0; m < s->nsa; m++)
			if (s->sa[m].sa.spi == k.sa[i].spi &&
			    addr_same(&s->sa[m].sa.dst, &k.sa[i].dst))
				break;
		if (m < s->nsa)
			sa_ours(a, &kept->sad->sad_entry.v[m], &k.sa[i], &sv[ns++],
			    &nomem);
		else
			sa_foreign(a, &k.sa[i], &sv[ns++], &nomem);
	}
	for (i = np = 0; !nomem && i < k.nsp; i++) {
		for (m = 0; sp_ours(&k.sp[i]) && m < s->nsp; m++)
			if (sp_sel_same(&s->sp[m].sp, &k.sp[i]))
				break;
		if (sp_ours(&k.sp[i]) && m < s->nsp)
			pv[np++] = kept->spd->spd_entry.v[m];
		else if (sp_foreign(a, &k.sp[i], &pv[np], &nomem))
			np++;
	}
	ks_free(&k);
	work_free(&w);
	if (nomem)
		return (ENOMEM);
	sad->sad_entry.n = ns;
	sad->sad_entry.v = sv;
	spd->spd_entry.n = np;
	spd->spd_entry.v = pv;
	c->sad = sad;
	c->spd = spd;
	*out = c;
	return (0);
}

/*
 * The lists: running's the controller's entries as kept; the
 * operational datastore's the kernel's SAD and SPD, all of them.
 */
int
ikeless_get(bool oper, cbl_yarena *a, struct ietf_i2nsf_ikeless *data)
{
	struct ietf_i2nsf_ikeless	 kept;
	struct ikl_set			 s;
	struct iklerr			 ie;
	int				 error;

	memset(&kept, 0, sizeof(kept));
	pthread_mutex_lock(&ikl_lock);
	error = kept_read(&kept, a);
	pthread_mutex_unlock(&ikl_lock);
	if (error != 0)
		return (error);
	if (!oper) {
		data->ipsec_ikeless = kept.ipsec_ikeless;
		return (0);
	}
	memset(&ie, 0, sizeof(ie));
	if (set_compile(kept.ipsec_ikeless, &s, &ie) != 0)
		memset(&s, 0, sizeof(s));
	error = operational(a, kept.ipsec_ikeless, &s, &data->ipsec_ikeless);
	set_free(&s);
	return (error);
}

/* ---- The start --------------------------------------------------------- */

/*
 * At the start: running's policies put back where the kernel has not
 * got them; its SAs the kernel has not got (a reboot's state loss, RFC
 * 9061 4.2, or a hard lifetime reached) taken out of running, for the
 * controller to send new ones.
 */
void
ikeless_start(void)
{
	struct ietf_i2nsf_ikeless	 kept, now;
	struct ikeless_rest {
		yikl	c;
		ysad	sad;
	}				*r;
	struct ikl_set			 s;
	struct iklerr			 ie;
	struct kstate			 k;
	struct work			 w;
	const struct pfkey_sp		*ksp;
	struct pfkey_sp			 sp;
	cbl_yarena			*a;
	ysa				*keep;
	const char			*e = NULL;
	char				 lost[512], err[256];
	size_t				 i, nk, nput;
	int				 fd;

	if ((a = cbl_yarena_new()) == NULL)
		return;
	memset(&kept, 0, sizeof(kept));
	memset(&ie, 0, sizeof(ie));
	pthread_mutex_lock(&ikl_lock);
	if (kept_read(&kept, a) != 0 || kept.ipsec_ikeless == NULL ||
	    set_compile(kept.ipsec_ikeless, &s, &ie) != 0) {
		if (ie.msg[0] != '\0')
			logmsg(LOG_ERR, "ipsec-ikeless: running's entries "
			    "cannot be put in: %s", ie.msg);
		goto out;
	}
	live_set(&s);
	work_init(&w);
	if ((fd = pfkey_open(&w, &e)) == -1 || ks_read(&w, fd, &k, &e) == -1) {
		logmsg(LOG_WARNING, "ipsec-ikeless: running's entries not put "
		    "back: %s", e);
		if (fd != -1)
			close(fd);
		work_free(&w);
		set_free(&s);
		goto out;
	}
	for (i = nput = 0; i < s.nsp; i++) {
		sp = s.sp[i].sp;
		if ((ksp = ks_find_sp(&k, &sp)) != NULL && sp_same(ksp, &sp))
			continue;
		if (ksp != NULL && !sp_ours(ksp)) {
			logmsg(LOG_WARNING, "ipsec-ikeless: policy %s not put "
			    "back: spd/%u, not the controller's, has its "
			    "selector", s.sp[i].name, ksp->id);
			continue;
		}
		if ((ksp != NULL ? pfkey_spdupdate(&w, fd, &sp, &e) :
		    pfkey_spdadd(&w, fd, &sp, &e)) == -1)
			logmsg(LOG_WARNING, "ipsec-ikeless: policy %s not put "
			    "back: %s", s.sp[i].name, e);
		else
			nput++;
	}
	if (nput > 0)
		logmsg(LOG_NOTICE, "ipsec-ikeless: %zu policies put back",
		    nput);
	close(fd);
	/* The SAs the kernel has not got leave running. */
	lost[0] = '\0';
	keep = NULL;
	nk = 0;
	if (s.nsa > 0 && (keep = cbl_yarena_alloc(a, s.nsa *
	    sizeof(*keep))) != NULL)
		for (i = 0; i < s.nsa; i++) {
			if (ks_find_sa(&k, &s.sa[i].sa) != NULL) {
				keep[nk++] = kept.ipsec_ikeless->sad->
				    sad_entry.v[i];
				continue;
			}
			snprintf(lost + strlen(lost), sizeof(lost) -
			    strlen(lost), "%s%s", lost[0] != '\0' ? ", " : "",
			    s.sa[i].name);
		}
	ks_free(&k);
	if (keep != NULL && nk < s.nsa &&
	    (r = cbl_yarena_alloc(a, sizeof(*r))) != NULL) {
		memset(r, 0, sizeof(*r));
		r->c = *kept.ipsec_ikeless;
		r->sad.sad_entry.n = nk;
		r->sad.sad_entry.v = keep;
		r->c.sad = &r->sad;
		now.ipsec_ikeless = &r->c;
		if (kept_write(&now, err, sizeof(err)) != 0)
			logmsg(LOG_ERR, "ipsec-ikeless: %s", err);
		else {
			logmsg(LOG_NOTICE, "ipsec-ikeless: %zu SAs gone with "
			    "the kernel's state taken out of running, for the "
			    "controller to send new ones (RFC 9061 4.2): %s",
			    s.nsa - nk, lost);
			set_free(&s);
			memset(&ie, 0, sizeof(ie));
			if (set_compile(&r->c, &s, &ie) == 0)
				live_set(&s);
		}
	}
	work_free(&w);
	set_free(&s);
out:
	pthread_mutex_unlock(&ikl_lock);
	cbl_yarena_free(a);
}
