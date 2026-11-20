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
 * an IKE daemon's, an ipsec(4) interface's own, by the kernel's own
 * key: an SA "esp/<destination>/0x<SPI>", a policy "spd/<id>".  Those
 * are never in running, so no edit touches them: an entry of the
 * controller's that would take one's SPI and destination, or one's
 * selector and direction, is refused (in-use) before anything is
 * changed.  A policy is the controller's by its priority, from
 * IKL_SP_BASE in the list's order (ordered-by user: the first wins),
 * after setkey's (0); an SA by its SPI and destination being one of
 * running's.
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
 *
 * Arcana's augments (arcana-ikeless, PLAN-SDN-YANG 6.2.5).  An SD-WAN
 * tunnel's SAs are derived by the agent: each end has an X25519 key pair
 * (key-pairs, sa.c), made with its entry and anew when its generation
 * changes; a derived sad-entry names its pair, the far end's public half,
 * an epoch and its direction and is given no SPI and no keys, which the
 * agent derives (HKDF-SHA256 of the agreement, as the ipsec-sa job did)
 * and keeps in running, so the same entry set again is no change and an
 * undone commit puts back keys it has.  An SA the same in all under
 * another name is no change to the kernel (a rotation's ".next" made the
 * tunnel's own); two derived entries of one SA but for their reqid (both
 * ends in one network, as the console's tests have them) are one; a
 * derived SA the kernel has already, of its reqid, mode and cipher (the
 * job's, before the update), is taken over as it is.  An entry with a
 * jail is of that vnet jail's network, by PF_KEY there: the jails are
 * changed after the host, a refused one putting back those before it;
 * the news, the counters and the kernel's own entries are the host's
 * network's alone.
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
typedef struct ietf_i2nsf_ikeless_ipsec_ikeless_sad_sad_entry_ipsec_sa_config_arcikl_derived
    yderived;
typedef struct ietf_i2nsf_ikeless_ipsec_ikeless_arcikl_key_pairs ykps;
typedef struct ietf_i2nsf_ikeless_ipsec_ikeless_arcikl_key_pairs_key_pair ykp;

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
#define	DERIVED_OUT	IETF_I2NSF_IKELESS_IPSEC_IKELESS_SAD_SAD_ENTRY_IPSEC_SA_CONFIG_ARCIKL_DERIVED_DIRECTION_OUTBOUND

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
	const char	*jail;		/* a vnet jail's network, or NULL */
	size_t		 idx;		/* its place in the list */
	struct pfkey_sa	 sa;
	unsigned char	 ek[IKL_KEY], ak[IKL_KEY];
	uint32_t	 idle_soft, idle_hard;	/* the agent's, seconds */
	const char	*pair;		/* derived: from this key pair */
	uint32_t	 lifetime;	/* derived: its keys' */
	bool		 out;		/* derived: outbound */
	bool		 aead;
};

/* An spd-entry as the kernel is given it. */
struct ikl_sp {
	const char	*name;
	const char	*jail;
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
	k->jail = e->arcikl_jail;
	if (strlen(name) >= IKL_NAME || name[0] == '\0')
		return (fault(ie, EINVAL, "sad/sad-entry/name", "sad-entry "
		    "\"%.40s\": a name of 1 to %d characters", name,
		    IKL_NAME - 1));
	if (name_kernels(name))
		return (fault(ie, EINVAL, "sad/sad-entry/name", "%s: esp/ and "
		    "spd/ name the kernel's own entries", name));
	if (c != NULL && c->arcikl_derived != NULL) {
		k->pair = c->arcikl_derived->key_pair;
		k->out = !c->arcikl_derived->has_direction ||
		    c->arcikl_derived->direction == DERIVED_OUT;
		k->lifetime = c->arcikl_derived->has_lifetime ?
		    c->arcikl_derived->lifetime : 0;
	}
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
	k->jail = e->arcikl_jail;
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

/* Whether two derived SAs are one but for their reqid: of one
 * derivation, the same ends, SPI and keys. */
static bool
sa_twin(const struct ikl_sa *a, const struct ikl_sa *b)
{
	struct ikl_sa	x = *b;
	bool		same;

	x.sa.reqid = a->sa.reqid;
	same = sa_same(a, &x);
	OPENSSL_cleanse(&x, sizeof(x));
	return (same);
}

/* Whether two entries are of one network: the host's (NULL) or a jail's. */
static bool
jail_same(const char *a, const char *b)
{

	return (a == NULL ? b == NULL : b != NULL && strcmp(a, b) == 0);
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
	struct ikl_sa	*k;
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
	for (i = 0; i < nsa; i++) {
		k = &s->sa[s->nsa];
		if (sa_compile(&sad->sad_entry.v[i], k, ie) != 0) {
			OPENSSL_cleanse(k, sizeof(*k));
			goto bad;
		}
		k->idx = i;
		for (j = 0; j < s->nsa; j++)
			if (jail_same(s->sa[j].jail, k->jail) &&
			    s->sa[j].sa.spi == k->sa.spi &&
			    addr_same(&s->sa[j].sa.dst, &k->sa.dst))
				break;
		/* Both ends of a tunnel in one network derive one SA
		 * twice, the same but each on its own interface's reqid:
		 * it is one, the first's. */
		if (j < s->nsa && s->sa[j].pair != NULL && k->pair != NULL &&
		    sa_twin(&s->sa[j], k)) {
			OPENSSL_cleanse(k, sizeof(*k));
			continue;
		}
		if (j < s->nsa) {
			fault(ie, EINVAL, "sad/sad-entry/ipsec-sa-config/spi",
			    "%s and %s: one SA, the same SPI to the same "
			    "destination", s->sa[j].name, k->name);
			s->nsa++;
			goto bad;
		}
		s->nsa++;
	}
	for (i = 0; i < nsp; i++, s->nsp++) {
		if (sp_compile(&spd->spd_entry.v[i], i, &s->sp[i], ie) != 0)
			goto bad;
		for (j = 0; j < i; j++)
			if (jail_same(s->sp[j].jail, s->sp[i].jail) &&
			    sp_sel_same(&s->sp[j].sp, &s->sp[i].sp)) {
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

/* The SA of s the same in all as k, whatever its name. */
static const struct ikl_sa *
set_sa_like(const struct ikl_set *s, const struct ikl_sa *k)
{

	for (size_t i = 0; i < s->nsa; i++)
		if (jail_same(s->sa[i].jail, k->jail) && sa_same(&s->sa[i], k))
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
    const struct ikl_set *all, struct iklerr *ie, size_t *nadd, size_t *ndel)
{
	struct kstate		 k;
	struct journal		 j;
	struct ikl_step		 st;
	const struct ikl_sp	*op;
	const struct pfkey_sa	*ksa;
	const struct pfkey_sp	*ksp;
	struct pfkey_sp		 sp;
	const char		*e = NULL, *ue = NULL;
	size_t			 i, m, m2 = 0;
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
	/* What differs: an SA the same in all under another name (a
	 * rotation's next made the one) is no change to the kernel. */
	for (i = 0; i < b->nsa; i++)
		sa_gone[i] = set_sa_like(n, &b->sa[i]) == NULL;
	for (i = 0; i < n->nsa; i++)
		sa_new[i] = set_sa_like(b, &n->sa[i]) == NULL;
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
		/* A derived SA the kernel has as derived, of its reqid, mode
		 * and cipher: the ipsec-sa job's before 6.2.5, the same
		 * derivation's.  Taken over as it is, never sent plain. */
		/* One derived in another network the same but its reqid:
		 * a kernel the two networks share (the agent's stand-in for
		 * PF_KEY), the SA there already. */
		for (m2 = 0; m == b->nsa && n->sa[i].pair != NULL && all !=
		    NULL && m2 < all->nsa; m2++)
			if (all->sa[m2].pair != NULL && !jail_same(all->sa[m2].jail,
			    n->sa[i].jail) && sa_twin(&all->sa[m2], &n->sa[i]))
				break;
		if (all != NULL && m == b->nsa && m2 < all->nsa) {
			sa_new[i] = false;
			continue;
		}
		if (m == b->nsa && n->sa[i].pair != NULL && ksa->reqid ==
		    n->sa[i].sa.reqid && ksa->mode == n->sa[i].sa.mode &&
		    ksa->ealg == n->sa[i].sa.ealg && addr_same(&ksa->src,
		    &n->sa[i].sa.src)) {
			sa_new[i] = false;
			logmsg(LOG_NOTICE, "ipsec-ikeless: %s: SA %#x, derived "
			    "before, taken over as it is", n->sa[i].name,
			    ksa->spi);
			continue;
		}
		if (m == b->nsa) {
			char	a[INET6_ADDRSTRLEN];

			addr_text(&ksa->dst, a, sizeof(a));
			fault(ie, EBUSY, "sad/sad-entry/ipsec-sa-config/spi",
			    "%s: the SA of SPI %#x to %s is the kernel's "
			    "already and not the controller's (setkey's, an "
			    "IKE daemon's): left as it is",
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
		    "controller's (setkey's, an IKE daemon's): left as it "
		    "is", n->sp[i].name, ksp->id);
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

/* ---- Networks ------------------------------------------------------- */

/* s's entries of the network jail (NULL: the host's) into out. */
static int
set_jail(const struct ikl_set *s, const char *jail, struct ikl_set *out)
{
	size_t	i;

	memset(out, 0, sizeof(*out));
	if ((out->sa = calloc(s->nsa + 1, sizeof(*out->sa))) == NULL ||
	    (out->sp = calloc(s->nsp + 1, sizeof(*out->sp))) == NULL) {
		set_free(out);
		return (-1);
	}
	for (i = 0; i < s->nsa; i++)
		if (jail_same(s->sa[i].jail, jail))
			out->sa[out->nsa++] = s->sa[i];
	for (i = 0; i < s->nsp; i++)
		if (jail_same(s->sp[i].jail, jail))
			out->sp[out->nsp++] = s->sp[i];
	return (0);
}

/* The jails the entries of b and n are of, each once, into v (room for
 * every entry); the host's not among them.  How many. */
static size_t
set_jails(const struct ikl_set *b, const struct ikl_set *n, const char **v)
{
	const struct ikl_set	*s;
	const char		*j;
	size_t			 i, k, m, nv = 0;

	for (k = 0; k < 2; k++) {
		s = k == 0 ? b : n;
		for (i = 0; i < s->nsa + s->nsp; i++) {
			j = i < s->nsa ? s->sa[i].jail : s->sp[i - s->nsa].jail;
			if (j == NULL)
				continue;
			for (m = 0; m < nv && strcmp(v[m], j) != 0; m++)
				;
			if (m == nv)
				v[nv++] = j;
		}
	}
	return (nv);
}

/* A PF_KEY socket in the network of jail (NULL: the host's), w working
 * there; -1 and why. */
static int
jail_pfkey(struct work *w, const char *jail, const char **errp)
{

	if (jail != NULL && scope_enter(w, jail, errp) != 0)
		return (-1);
	return (pfkey_open(w, errp));
}

/* The kernel of jail moved from b's entries of it to n's. */
static int
apply_jail(const char *jail, const struct ikl_set *b, const struct ikl_set *n,
    struct iklerr *ie, size_t *nadd, size_t *ndel)
{
	struct ikl_set	 bj, nj;
	struct work	 w;
	const char	*e = NULL;
	int		 fd, rc = -1;

	work_init(&w);
	if (set_jail(b, jail, &bj) != 0 || set_jail(n, jail, &nj) != 0) {
		set_free(&bj);
		work_free(&w);
		return (fault(ie, ENOMEM, NULL, "out of memory"));
	}
	if (bj.nsa + bj.nsp + nj.nsa + nj.nsp == 0)
		rc = 0;
	else if ((fd = jail_pfkey(&w, jail, &e)) == -1) {
		/* A jail gone has none of its SAs and policies left to
		 * take out. */
		if (jail != NULL && nj.nsa + nj.nsp == 0)
			rc = 0;
		else
			fault(ie, EIO, NULL, "%s%s%s", jail != NULL ? jail :
			    "", jail != NULL ? ": " : "", e);
	} else {
		rc = apply(&w, fd, &bj, &nj, n, ie, nadd, ndel);
		close(fd);
	}
	/* The entries' copies: their keys cleansed by set_free(). */
	set_free(&bj);
	set_free(&nj);
	work_free(&w);
	return (rc);
}

/* ---- Key pairs and derived SAs ------------------------------------- */

static void	*aalloc(cbl_yarena *, size_t, bool *);
static const char *astr(cbl_yarena *, const char *, bool *);

/* A pair as an edit changed it, for undoing it. */
struct kp_step {
	const char	*name;
	int		 how;
	uint32_t	 was, gen;
};

static const ykp *
kp_find(const yikl *c, const char *name)
{
	const ykps	*k = c != NULL ? c->arcikl_key_pairs : NULL;

	for (size_t i = 0; k != NULL && i < k->key_pair.n; i++)
		if (strcmp(k->key_pair.v[i].name, name) == 0)
			return (&k->key_pair.v[i]);
	return (NULL);
}

/* The jail a pair's name says, "ipsec0@web", or NULL. */
static const char *
kp_jail(const char *name)
{
	const char	*at;

	return ((at = strchr(name, '@')) != NULL ? at + 1 : NULL);
}

/* The pairs of n made, turned or put back as running (b) had them,
 * each step into v (room for n's); -1 and why, those before undone. */
static int
kp_apply(const yikl *b, const yikl *n, struct kp_step *v, size_t *nv,
    struct iklerr *ie)
{
	const ykps	*k = n != NULL ? n->arcikl_key_pairs : NULL;
	const ykp	*p, *o;
	char		 err[256];

	*nv = 0;
	for (size_t i = 0; k != NULL && i < k->key_pair.n; i++) {
		p = &k->key_pair.v[i];
		o = kp_find(b, p->name);
		v[*nv].name = p->name;
		v[*nv].was = o != NULL && o->has_generation ? o->generation : 0;
		v[*nv].gen = p->has_generation ? p->generation : 0;
		if (sa_pair_set(p->name, o != NULL, v[*nv].was, v[*nv].gen,
		    &v[*nv].how, err, sizeof(err)) != 0) {
			while (*nv > 0) {
				(*nv)--;
				sa_pair_unset(v[*nv].name, v[*nv].how,
				    v[*nv].was, v[*nv].gen);
			}
			return (fault(ie, EIO, NULL, "key-pair %s: %s", p->name,
			    err));
		}
		(*nv)++;
	}
	return (0);
}

/* A derived SA's lengths: its encryption key (AES-GCM's salt after it)
 * and its integrity key, as its algorithms take them; -1 and why. */
static int
derived_lens(const ysa *e, size_t *enclen, size_t *authlen,
    struct iklerr *ie)
{
	const yespsa	*es = e->ipsec_sa_config->esp_sa;
	uint16_t	 ealg, aalg;

	ealg = es != NULL && es->encryption != NULL &&
	    es->encryption->has_encryption_algorithm ?
	    es->encryption->encryption_algorithm : IANA_ENCR_AES_CBC;
	aalg = es != NULL && es->integrity != NULL &&
	    es->integrity->has_integrity_algorithm ?
	    es->integrity->integrity_algorithm : 12;
	*authlen = 0;
	if (ealg == IANA_ENCR_AES_GCM_16) {
		*enclen = 36;
		return (0);
	}
	if (ealg != IANA_ENCR_AES_CBC)
		return (fault(ie, EOPNOTSUPP, "sad/sad-entry/ipsec-sa-config/"
		    "esp-sa/encryption/encryption-algorithm", "%s: encryption "
		    "%u: a derived SA's are 12 (AES-CBC) and 20 (AES-GCM-16)",
		    e->name, ealg));
	*enclen = 32;
	for (size_t j = 0; j < nitems(ints); j++)
		if (ints[j].iana == aalg)
			*authlen = ints[j].keylen[0];
	if (*authlen == 0)
		return (fault(ie, EOPNOTSUPP, "sad/sad-entry/ipsec-sa-config/"
		    "esp-sa/integrity/integrity-algorithm", "%s: integrity %u: "
		    "taken are 2, 12, 13 and 14", e->name, aalg));
	return (0);
}

/* Whether running's entry r was derived from what e is to be, its SPI
 * and keys in it. */
static bool
derived_kept(const ysa *e, const ysa *r)
{
	const yderived	*d = e->ipsec_sa_config->arcikl_derived, *rd;
	const ysacfg	*c = e->ipsec_sa_config, *rc;
	const yespsa	*x, *y;

	if (r == NULL || (rc = r->ipsec_sa_config) == NULL || !rc->has_spi ||
	    (rd = rc->arcikl_derived) == NULL || !jail_same(e->arcikl_jail,
	    r->arcikl_jail) || strcmp(d->key_pair, rd->key_pair) != 0 ||
	    d->peer.len != rd->peer.len || memcmp(d->peer.p, rd->peer.p,
	    d->peer.len) != 0 || (d->has_epoch ? d->epoch : 0) !=
	    (rd->has_epoch ? rd->epoch : 0) || (d->has_direction ?
	    d->direction : DERIVED_OUT) != (rd->has_direction ?
	    rd->direction : DERIVED_OUT))
		return (false);
	x = c->esp_sa;
	y = rc->esp_sa;
	if (y == NULL || y->encryption == NULL || y->encryption->key == NULL)
		return (false);
	return ((x != NULL && x->encryption != NULL &&
	    x->encryption->has_encryption_algorithm ?
	    x->encryption->encryption_algorithm : IANA_ENCR_AES_CBC) ==
	    (y->encryption->has_encryption_algorithm ?
	    y->encryption->encryption_algorithm : IANA_ENCR_AES_CBC) &&
	    (x != NULL && x->integrity != NULL &&
	    x->integrity->has_integrity_algorithm ?
	    x->integrity->integrity_algorithm : 12) == (y->integrity != NULL &&
	    y->integrity->has_integrity_algorithm ?
	    y->integrity->integrity_algorithm : 12));
}

static const char *
ahex(cbl_yarena *a, const unsigned char *raw, size_t n, bool *nomem)
{
	static const char	digits[] = "0123456789abcdef";
	char			*s;

	/* yang:hex-string's, the bytes by colons. */
	if ((s = aalloc(a, 3 * n + 1, nomem)) == NULL)
		return (NULL);
	for (size_t i = 0; i < n; i++) {
		s[3 * i] = digits[raw[i] >> 4];
		s[3 * i + 1] = digits[raw[i] & 15];
		s[3 * i + 2] = i + 1 < n ? ':' : '\0';
	}
	return (s);
}

/*
 * c with each derived sad-entry's SPI and keys: running's (was) where
 * it was derived there from the same, else derived now from its pair
 * and the far half.  An entry not in running given an SPI or keys is
 * refused: they are the agent's.  *out is c itself when nothing is
 * derived; -1 and why.
 */
static int
derive_fill(cbl_yarena *a, const yikl *was, const yikl *c, const yikl **out,
    struct iklerr *ie)
{
	const ysad	*rs = was != NULL ? was->sad : NULL;
	const ysa	*e, *r;
	const yderived	*d;
	yikl		*nc;
	ysad		*ns;
	ysa		*nv;
	ysacfg		*cfg;
	yespsa		*es;
	yenc		*en;
	yint		*in;
	unsigned char	 ek[IKL_KEY], ak[IKL_KEY];
	char		 err[256];
	size_t		 i, m, enclen, authlen;
	uint32_t	 spi;
	bool		 nomem = false, any = false;

	*out = c;
	for (i = 0; c != NULL && c->sad != NULL && i < c->sad->sad_entry.n; i++)
		if (c->sad->sad_entry.v[i].ipsec_sa_config != NULL &&
		    c->sad->sad_entry.v[i].ipsec_sa_config->arcikl_derived !=
		    NULL)
			any = true;
	if (!any)
		return (0);
	nc = aalloc(a, sizeof(*nc), &nomem);
	ns = aalloc(a, sizeof(*ns), &nomem);
	nv = aalloc(a, c->sad->sad_entry.n * sizeof(*nv), &nomem);
	if (nomem)
		return (fault(ie, ENOMEM, NULL, "out of memory"));
	*nc = *c;
	*ns = *c->sad;
	for (i = 0; i < c->sad->sad_entry.n; i++) {
		e = &c->sad->sad_entry.v[i];
		nv[i] = *e;
		if (e->ipsec_sa_config == NULL || (d =
		    e->ipsec_sa_config->arcikl_derived) == NULL)
			continue;
		if (d->key_pair == NULL || kp_find(c, d->key_pair) == NULL)
			return (fault(ie, EINVAL, "sad/sad-entry/ipsec-sa-config",
			    "%s: derived from key pair %s, which is not among "
			    "the key-pairs", e->name, d->key_pair != NULL ?
			    d->key_pair : "(none)"));
		if (!jail_same(kp_jail(d->key_pair), e->arcikl_jail))
			return (fault(ie, EINVAL, "sad/sad-entry/ipsec-sa-config",
			    "%s: key pair %s is %s, the SA %s%s", e->name,
			    d->key_pair, kp_jail(d->key_pair) != NULL ?
			    "a jail's" : "the host's", e->arcikl_jail != NULL ?
			    "the jail " : "the host's", e->arcikl_jail != NULL ?
			    e->arcikl_jail : ""));
		if (d->peer.len != SA_PUB_LEN)
			return (fault(ie, EINVAL, "sad/sad-entry/ipsec-sa-config",
			    "%s: peer is the far end's public half, %d bytes",
			    e->name, SA_PUB_LEN));
		if (derived_lens(e, &enclen, &authlen, ie) != 0)
			return (-1);
		for (m = 0, r = NULL; rs != NULL && m < rs->sad_entry.n; m++)
			if (strcmp(rs->sad_entry.v[m].name, e->name) == 0)
				r = &rs->sad_entry.v[m];
		cfg = aalloc(a, sizeof(*cfg), &nomem);
		es = aalloc(a, sizeof(*es), &nomem);
		en = aalloc(a, sizeof(*en), &nomem);
		in = aalloc(a, sizeof(*in), &nomem);
		if (nomem)
			return (fault(ie, ENOMEM, NULL, "out of memory"));
		*cfg = *e->ipsec_sa_config;
		if (cfg->esp_sa != NULL)
			*es = *cfg->esp_sa;
		if (es->encryption != NULL)
			*en = *es->encryption;
		if (es->integrity != NULL)
			*in = *es->integrity;
		if (derived_kept(e, r)) {
			/* As derived before: running's. */
			cfg->spi = r->ipsec_sa_config->spi;
			en->key = r->ipsec_sa_config->esp_sa->encryption->key;
			in->key = r->ipsec_sa_config->esp_sa->integrity != NULL ?
			    r->ipsec_sa_config->esp_sa->integrity->key : NULL;
		} else {
			if (r == NULL && (cfg->has_spi || en->key != NULL ||
			    en->iv != NULL || in->key != NULL))
				return (fault(ie, EINVAL, "sad/sad-entry/"
				    "ipsec-sa-config/spi", "%s: a derived SA is "
				    "given no SPI and no keys: they are the "
				    "agent's", e->name));
			if (sa_pair_derive(d->key_pair, d->peer.p, d->has_epoch ?
			    d->epoch : 0, !d->has_direction || d->direction ==
			    DERIVED_OUT, enclen, authlen, &spi, ek, ak, err,
			    sizeof(err)) != 0)
				return (fault(ie, EINVAL, "sad/sad-entry/"
				    "ipsec-sa-config", "%s: %s", e->name, err));
			cfg->spi = spi;
			en->key = ahex(a, ek, enclen, &nomem);
			in->key = authlen > 0 ? ahex(a, ak, authlen, &nomem) :
			    NULL;
			OPENSSL_cleanse(ek, sizeof(ek));
			OPENSSL_cleanse(ak, sizeof(ak));
			if (nomem)
				return (fault(ie, ENOMEM, NULL, "out of memory"));
		}
		cfg->has_spi = true;
		en->iv = NULL;
		es->encryption = en;
		es->integrity = in->key != NULL || in->has_integrity_algorithm ?
		    in : NULL;
		cfg->esp_sa = es;
		nv[i].ipsec_sa_config = cfg;
	}
	ns->sad_entry.v = nv;
	nc->sad = ns;
	*out = nc;
	return (0);
}

/* Whether a pair's derived SAs differ between b and n. */
static bool
pair_moved(const struct ikl_set *b, const struct ikl_set *n, const char *pair)
{
	const struct ikl_set	*s, *o;

	for (size_t k = 0; k < 2; k++) {
		s = k == 0 ? b : n;
		o = k == 0 ? n : b;
		for (size_t i = 0; i < s->nsa; i++)
			if (s->sa[i].pair != NULL && strcmp(s->sa[i].pair,
			    pair) == 0 && set_sa_like(o, &s->sa[i]) == NULL)
				return (true);
	}
	return (false);
}

/*
 * After an edit (ok, or refused why): each pair's derived SAs kept for
 * the sdwan read (the last of each direction in the list's order, the
 * newest; two of one direction, a rotation half done), and the
 * key-rotation faults: a pair whose SAs an edit could not change has
 * one, until an edit leaves it one SA a direction.
 */
static void
pairs_told(const yikl *c, const struct ikl_set *b, const struct ikl_set *n,
    const char *why)
{
	const ykps	*k = c != NULL ? c->arcikl_key_pairs : NULL;
	const char	*name;
	uint32_t	 spi_out, spi_in, life;
	size_t		 i, j, nout, nin;

	for (i = 0; k != NULL && i < k->key_pair.n; i++) {
		name = k->key_pair.v[i].name;
		spi_out = spi_in = life = 0;
		nout = nin = 0;
		for (j = 0; j < n->nsa; j++) {
			if (n->sa[j].pair == NULL || strcmp(n->sa[j].pair,
			    name) != 0)
				continue;
			if (n->sa[j].out) {
				nout++;
				spi_out = n->sa[j].sa.spi;
				life = n->sa[j].lifetime;
			} else {
				nin++;
				spi_in = n->sa[j].sa.spi;
			}
		}
		if (why != NULL) {
			if (pair_moved(b, n, name))
				sa_rotation_fault(name, why);
			continue;
		}
		sa_pair_state(name, spi_out, spi_in, life, nout > 1 || nin > 1);
		if (nout == 1 && nin == 1 && pair_moved(b, n, name))
			sa_rotation_fault(name, NULL);
	}
	if (why == NULL)
		sa_rotation_fault(NULL, NULL);
}

/*
 * after's entries made the kernel's, then kept; refused, an errno, why
 * in err and the node at fault in *sid (0: the container), the kernel
 * and running as they were.  The key pairs first (made, turned, put
 * back), then the derived SAs' SPIs and keys, then each network's SAs
 * and policies, the host's and each jail's; a jail's refused puts back
 * those done before it.
 */
int
ikeless_edit(const struct ietf_i2nsf_ikeless *after, char *err,
    size_t errlen, uint64_t *sid)
{
	struct ietf_i2nsf_ikeless	 kept, filled;
	struct ikl_set			 b, n, host;
	struct iklerr			 ie, ue;
	struct kp_step			*kv = NULL;
	cbl_yarena			*a;
	const yikl			*was, *now;
	const char			**jails = NULL;
	const ykps			*kps;
	size_t				 nadd, ndel, nkv = 0, nj, i, done, x;
	int				 rc = -1;

	memset(&ie, 0, sizeof(ie));
	memset(&b, 0, sizeof(b));
	memset(&n, 0, sizeof(n));
	*sid = 0;
	if ((a = cbl_yarena_new()) == NULL) {
		snprintf(err, errlen, "out of memory");
		return (ENOMEM);
	}
	pthread_mutex_lock(&ikl_lock);
	memset(&kept, 0, sizeof(kept));
	if (kept_read(&kept, a) != 0 || set_compile(kept.ipsec_ikeless, &b,
	    &ie) != 0) {
		/* Running unreadable: what the kernel has of it is left. */
		logmsg(LOG_ERR, "ipsec-ikeless: running's entries could not "
		    "be read: %s", ie.msg);
		memset(&b, 0, sizeof(b));
		memset(&ie, 0, sizeof(ie));
		kept.ipsec_ikeless = NULL;
	}
	was = kept.ipsec_ikeless;
	now = after != NULL ? after->ipsec_ikeless : NULL;
	kps = now != NULL ? now->arcikl_key_pairs : NULL;
	if ((kv = calloc((kps != NULL ? kps->key_pair.n : 0) + 1,
	    sizeof(*kv))) == NULL) {
		fault(&ie, ENOMEM, NULL, "out of memory");
		goto out;
	}
	if (kp_apply(was, now, kv, &nkv, &ie) != 0)
		goto out;
	if (derive_fill(a, was, now, &now, &ie) != 0 ||
	    set_compile(now, &n, &ie) != 0)
		goto undo_pairs;
	/* The host's network, then each jail's. */
	if ((jails = calloc(b.nsa + b.nsp + n.nsa + n.nsp + 1,
	    sizeof(*jails))) == NULL) {
		fault(&ie, ENOMEM, NULL, "out of memory");
		goto undo_pairs;
	}
	nj = set_jails(&b, &n, jails);
	/* A jail the new entries are of, running with a network of its
	 * own, or nothing is done. */
	for (i = 0; i < nj; i++) {
		struct ikl_set	 t;
		struct work	 w;
		const char	*e = NULL;
		bool		 some;

		if (set_jail(&n, jails[i], &t) != 0) {
			fault(&ie, ENOMEM, NULL, "out of memory");
			goto undo_pairs;
		}
		some = t.nsa + t.nsp > 0;
		set_free(&t);
		work_init(&w);
		if (some && scope_enter(&w, jails[i], &e) != 0) {
			fault(&ie, EINVAL, NULL, "%s", e);
			work_free(&w);
			goto undo_pairs;
		}
		work_free(&w);
	}
	nadd = ndel = 0;
	for (done = 0; done <= nj; done++)
		if (apply_jail(done == 0 ? NULL : jails[done - 1], &b, &n, &ie,
		    &x, &x) != 0)
			break;
	if (done <= nj) {
		/* Those done before put back as running has them. */
		for (i = done; i > 0; i--) {
			memset(&ue, 0, sizeof(ue));
			if (apply_jail(i == 1 ? NULL : jails[i - 2], &n, &b, &ue,
			    &x, &x) != 0)
				snprintf(ie.msg + strlen(ie.msg), sizeof(ie.msg) -
				    strlen(ie.msg), "; %s not put back: %s", i ==
				    1 ? "the host" : jails[i - 2], ue.msg);
		}
		goto undo_pairs;
	}
	filled.ipsec_ikeless = now;
	if (kept_write(&filled, ie.msg, sizeof(ie.msg)) != 0) {
		ie.error = EIO;
		for (i = nj + 1; i > 0; i--) {
			memset(&ue, 0, sizeof(ue));
			(void)apply_jail(i == 1 ? NULL : jails[i - 2], &n, &b, &ue,
			    &x, &x);
		}
		goto undo_pairs;
	}
	/* The pairs no entry has any more. */
	kps = was != NULL ? was->arcikl_key_pairs : NULL;
	for (i = 0; kps != NULL && i < kps->key_pair.n; i++)
		if (kp_find(now, kps->key_pair.v[i].name) == NULL)
			sa_pair_drop(kps->key_pair.v[i].name);
	if (set_jail(&n, NULL, &host) == 0) {
		live_set(&host);
		set_free(&host);
	}
	pairs_told(now, &b, &n, NULL);
	for (i = 0; i < n.nsa; i++)
		nadd += set_sa_like(&b, &n.sa[i]) == NULL;
	for (i = 0; i < b.nsa; i++)
		ndel += set_sa_like(&n, &b.sa[i]) == NULL;
	logmsg(LOG_NOTICE, "ipsec-ikeless: %zu SAs and %zu policies in %zu "
	    "networks; %zu SAs put in, %zu taken out", n.nsa, n.nsp, nj + 1,
	    nadd, ndel);
	rc = 0;
	goto out;
undo_pairs:
	pairs_told(was, &b, n.nsa > 0 ? &n : &b, ie.msg);
	while (nkv > 0) {
		nkv--;
		sa_pair_unset(kv[nkv].name, kv[nkv].how, kv[nkv].was,
		    kv[nkv].gen);
	}
out:
	pthread_mutex_unlock(&ikl_lock);
	free(kv);
	free(jails);
	set_free(&b);
	set_free(&n);
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
 * left out, and the kernel's state of it (none read, sa NULL: a jail's
 * network not there). */
static void
sa_ours(cbl_yarena *a, const ysa *e, const struct pfkey_sa *sa, ysa *out,
    bool *nomem)
{
	ysacfg	*c;
	yespsa	*es;
	yenc	*en;
	yint	*in;

	*out = *e;
	out->ipsec_sa_state = sa != NULL ? sa_state(a, sa, nomem) : NULL;
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

/* The kernel of jail's SAD and SPD (NULL: the host's) into k; false
 * when there is none (no PF_KEY, the jail not running). */
static bool
oper_read(const char *jail, struct kstate *k)
{
	struct work	 w;
	const char	*e = NULL;
	int		 fd;
	bool		 ok;

	memset(k, 0, sizeof(*k));
	work_init(&w);
	w.nice = true;
	if ((fd = jail_pfkey(&w, jail, &e)) == -1) {
		work_free(&w);
		return (false);
	}
	ok = ks_read(&w, fd, k, &e) == 0;
	if (!ok)
		logmsg(LOG_INFO, "a read of ipsec-ikeless%s%s failed: %s", jail !=
		    NULL ? " in " : "", jail != NULL ? jail : "", e);
	close(fd);
	work_free(&w);
	return (ok);
}

/* The key pairs as running has them, each with its public half. */
static const ykps *
oper_pairs(cbl_yarena *a, const yikl *kept, bool *nomem)
{
	const ykps	*k = kept != NULL ? kept->arcikl_key_pairs : NULL;
	ykps		*o;
	ykp		*v;
	unsigned char	*pub;

	if (k == NULL)
		return (NULL);
	o = aalloc(a, sizeof(*o), nomem);
	v = aalloc(a, (k->key_pair.n + 1) * sizeof(*v), nomem);
	if (*nomem)
		return (NULL);
	for (size_t i = 0; i < k->key_pair.n; i++) {
		v[i] = k->key_pair.v[i];
		if ((pub = aalloc(a, SA_PUB_LEN, nomem)) != NULL &&
		    sa_pair_public(v[i].name, pub)) {
			v[i].public.p = pub;
			v[i].public.len = SA_PUB_LEN;
		}
	}
	o->key_pair.n = k->key_pair.n;
	o->key_pair.v = v;
	return (o);
}

/* The kernel's SAD and SPD as the lists, the controller's entries
 * by their names: the host's every SA and policy, a jail's the
 * controller's alone (without their state where its network is not
 * there); the key pairs with their public halves. */
static int
operational(cbl_yarena *a, const yikl *kept, const struct ikl_set *s,
    const yikl **out)
{
	struct kstate		*ks, k;
	const char		**jails;
	yikl			*c;
	ysad			*sad;
	yspd			*spd;
	ysa			*sv;
	ysp			*pv;
	const char		*jail;
	size_t			 i, m, ns, np, nj, jx, tsa, tsp;
	bool			 nomem = false, *got;

	*out = NULL;
	jails = calloc(s->nsa + s->nsp + 1, sizeof(*jails));
	ks = calloc(s->nsa + s->nsp + 2, sizeof(*ks));
	got = calloc(s->nsa + s->nsp + 2, sizeof(*got));
	if (jails == NULL || ks == NULL || got == NULL) {
		free(jails);
		free(ks);
		free(got);
		return (ENOMEM);
	}
	nj = set_jails(s, s, jails);
	tsa = s->nsa;
	tsp = s->nsp;
	for (jx = 0; jx <= nj; jx++) {
		got[jx] = oper_read(jx == 0 ? NULL : jails[jx - 1], &ks[jx]);
		tsa += ks[jx].nsa;
		tsp += ks[jx].nsp;
	}
	c = aalloc(a, sizeof(*c), &nomem);
	sad = aalloc(a, sizeof(*sad), &nomem);
	spd = aalloc(a, sizeof(*spd), &nomem);
	sv = aalloc(a, (tsa + 1) * sizeof(*sv), &nomem);
	pv = aalloc(a, (tsp + 1) * sizeof(*pv), &nomem);
	ns = np = 0;
	for (jx = 0; !nomem && jx <= nj; jx++) {
		jail = jx == 0 ? NULL : jails[jx - 1];
		k = ks[jx];
		for (i = 0; !nomem && i < k.nsa; i++) {
			for (m = 0; m < s->nsa; m++)
				if (jail_same(s->sa[m].jail, jail) &&
				    s->sa[m].sa.spi == k.sa[i].spi &&
				    addr_same(&s->sa[m].sa.dst, &k.sa[i].dst))
					break;
			if (m < s->nsa)
				sa_ours(a, &kept->sad->sad_entry.v[s->sa[m].idx],
				    &k.sa[i], &sv[ns++], &nomem);
			else if (jail == NULL)
				sa_foreign(a, &k.sa[i], &sv[ns++], &nomem);
		}
		for (i = 0; !nomem && i < k.nsp; i++) {
			for (m = 0; sp_ours(&k.sp[i]) && m < s->nsp; m++)
				if (jail_same(s->sp[m].jail, jail) &&
				    sp_sel_same(&s->sp[m].sp, &k.sp[i]))
					break;
			if (sp_ours(&k.sp[i]) && m < s->nsp)
				pv[np++] = kept->spd->spd_entry.v[m];
			else if (jail == NULL && sp_foreign(a, &k.sp[i], &pv[np],
			    &nomem))
				np++;
		}
		/* A jail not there: its entries as running has them (no
		 * PF_KEY on the host, no ipsec.ko: none). */
		for (m = 0; !got[jx] && jail != NULL && !nomem && m < s->nsa;
		    m++)
			if (jail_same(s->sa[m].jail, jail))
				sa_ours(a, &kept->sad->sad_entry.v[s->sa[m].idx],
				    NULL, &sv[ns++], &nomem);
		for (m = 0; !got[jx] && jail != NULL && !nomem && m < s->nsp;
		    m++)
			if (jail_same(s->sp[m].jail, jail))
				pv[np++] = kept->spd->spd_entry.v[m];
	}
	for (jx = 0; jx <= nj; jx++)
		ks_free(&ks[jx]);
	free(ks);
	free(got);
	free(jails);
	c->arcikl_key_pairs = oper_pairs(a, kept, &nomem);
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
 * At the start, in each network (the host's, each jail's): running's
 * policies put back where the kernel has not got them; its SAs the
 * kernel has not got (a reboot's state loss, RFC 9061 4.2, a hard
 * lifetime reached, a jail stopped) taken out of running, for the
 * controller to send new ones.  A jail not running has none of its SAs,
 * and its policies are not put back.
 */
void
ikeless_start(void)
{
	struct ietf_i2nsf_ikeless	 kept, now;
	struct ikeless_rest {
		yikl	c;
		ysad	sad;
	}				*r;
	struct ikl_set			 s, host;
	struct iklerr			 ie;
	struct kstate			 k;
	struct work			 w;
	const struct pfkey_sp		*ksp;
	struct pfkey_sp			 sp;
	cbl_yarena			*a;
	const char			**jails = NULL, *jail;
	ysa				*keep;
	const char			*e = NULL;
	char				 lost[512], err[256];
	const ykps			*kps;
	bool				*found = NULL;
	size_t				 i, nk, nput, nj, jx;
	uint32_t			 gen;
	int				 fd, how;

	if ((a = cbl_yarena_new()) == NULL)
		return;
	memset(&kept, 0, sizeof(kept));
	memset(&ie, 0, sizeof(ie));
	memset(&s, 0, sizeof(s));
	pthread_mutex_lock(&ikl_lock);
	if (kept_read(&kept, a) != 0 || kept.ipsec_ikeless == NULL ||
	    set_compile(kept.ipsec_ikeless, &s, &ie) != 0) {
		if (ie.msg[0] != '\0')
			logmsg(LOG_ERR, "ipsec-ikeless: running's entries "
			    "cannot be put in: %s", ie.msg);
		goto out;
	}
	/* A pair running names and its file gone (a host reinstalled, its
	 * configuration kept): made anew, told. */
	if ((kps = kept.ipsec_ikeless->arcikl_key_pairs) != NULL)
		for (i = 0; i < kps->key_pair.n; i++) {
			gen = kps->key_pair.v[i].has_generation ?
			    kps->key_pair.v[i].generation : 0;
			if (sa_pair_set(kps->key_pair.v[i].name, true, gen, gen,
			    &how, err, sizeof(err)) != 0)
				logmsg(LOG_WARNING, "ipsec-ikeless: %s", err);
		}
	if (set_jail(&s, NULL, &host) == 0) {
		live_set(&host);
		set_free(&host);
	}
	jails = calloc(s.nsa + s.nsp + 1, sizeof(*jails));
	found = calloc(s.nsa + 1, sizeof(*found));
	if (jails == NULL || found == NULL)
		goto out;
	nj = set_jails(&s, &s, jails);
	for (jx = 0; jx <= nj; jx++) {
		jail = jx == 0 ? NULL : jails[jx - 1];
		work_init(&w);
		if ((fd = jail_pfkey(&w, jail, &e)) == -1 || ks_read(&w, fd, &k,
		    &e) == -1) {
			logmsg(LOG_WARNING, "ipsec-ikeless: running's entries%s%s "
			    "not put back: %s", jail != NULL ? " of " : "",
			    jail != NULL ? jail : "", e);
			if (fd != -1)
				close(fd);
			work_free(&w);
			/* The host's left as they are; a jail's SAs gone. */
			for (i = 0; jail == NULL && i < s.nsa; i++)
				if (s.sa[i].jail == NULL)
					found[i] = true;
			continue;
		}
		for (i = nput = 0; i < s.nsp; i++) {
			if (!jail_same(s.sp[i].jail, jail))
				continue;
			sp = s.sp[i].sp;
			if ((ksp = ks_find_sp(&k, &sp)) != NULL && sp_same(ksp,
			    &sp))
				continue;
			if (ksp != NULL && !sp_ours(ksp)) {
				logmsg(LOG_WARNING, "ipsec-ikeless: policy %s not "
				    "put back: spd/%u, not the controller's, has "
				    "its selector", s.sp[i].name, ksp->id);
				continue;
			}
			if ((ksp != NULL ? pfkey_spdupdate(&w, fd, &sp, &e) :
			    pfkey_spdadd(&w, fd, &sp, &e)) == -1)
				logmsg(LOG_WARNING, "ipsec-ikeless: policy %s not "
				    "put back: %s", s.sp[i].name, e);
			else
				nput++;
		}
		if (nput > 0)
			logmsg(LOG_NOTICE, "ipsec-ikeless: %zu policies%s%s put "
			    "back", nput, jail != NULL ? " of " : "", jail !=
			    NULL ? jail : "");
		close(fd);
		for (i = 0; i < s.nsa; i++)
			if (jail_same(s.sa[i].jail, jail) && ks_find_sa(&k,
			    &s.sa[i].sa) != NULL)
				found[i] = true;
		ks_free(&k);
		work_free(&w);
	}
	/* The SAs the kernel has not got leave running. */
	lost[0] = '\0';
	keep = NULL;
	nk = 0;
	if (s.nsa > 0 && (keep = cbl_yarena_alloc(a, s.nsa *
	    sizeof(*keep))) != NULL)
		for (i = 0; i < s.nsa; i++) {
			if (found[i]) {
				keep[nk++] = kept.ipsec_ikeless->sad->
				    sad_entry.v[s.sa[i].idx];
				continue;
			}
			snprintf(lost + strlen(lost), sizeof(lost) -
			    strlen(lost), "%s%s", lost[0] != '\0' ? ", " : "",
			    s.sa[i].name);
		}
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
			if (set_compile(&r->c, &s, &ie) == 0 &&
			    set_jail(&s, NULL, &host) == 0) {
				live_set(&host);
				set_free(&host);
			}
		}
	}
out:
	pthread_mutex_unlock(&ikl_lock);
	free(jails);
	free(found);
	set_free(&s);
	cbl_yarena_free(a);
}
