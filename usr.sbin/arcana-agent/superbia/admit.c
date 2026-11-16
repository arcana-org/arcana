/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Superbia: who may ask, and what.  A host's certificate is for a server
 * and a client both, so that hosts can reach each other (the mesh), and
 * it says so: a SAN URI urn:arcana:role:agent.  A peer that shows one is
 * another host, and asks nothing here but the mesh's, which there is
 * none of yet: it is refused.  The console's own certificate says
 * urn:arcana:role:console, and only a peer over TLS that shows it is
 * the console; one that says neither (a certificate from before the
 * roles, a host's among them) asks nothing.  peer_kind() decides it,
 * for the user of a request, agent-update and what a job records.
 *
 * What a request may do is NACM's (RFC 8341), as cblink checks it
 * (ynacm.c has the rules): its user is the one the console says it asks
 * for, the console's own requests user "console"; root, or the user the
 * agent runs as, on the unix socket is the recovery session, which may
 * say a user too (who can write the rules' file needs no rule); another
 * local user is its login name.  Every rpc and action of the models is
 * NACM's; those that change the host, or give out what should stay on
 * it, are marked nacm:default-deny-all: run only by a rule that permits
 * them.  So are the commands of the agent's own stream families.
 */

#include <sys/param.h>

#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "agent.h"
#include "ystream.h"

#define	ROLE_AGENT	"URI:urn:arcana:role:agent"
#define	ROLE_CONSOLE	"URI:urn:arcana:role:console"

/* Does the peer's certificate say the role? */
static bool
has_role(const cbl_peer *p, const char *role)
{
	size_t	i, n;

	n = cbl_peer_san_count(p);
	for (i = 0; i < n; i++)
		if (cbl_peer_san(p, i) != NULL && strcmp(cbl_peer_san(p, i),
		    role) == 0)
			return (true);
	return (false);
}

/* Is the peer another host? */
bool
peer_is_host(const cbl_peer *p)
{

	return (p != NULL && has_role(p, ROLE_AGENT));
}

/* Whether uid is in the socket's group (-g), the console's by the
 * configuration: its own, or one it is a member of. */
static bool
in_sock_group(uid_t uid, gid_t gid)
{
	struct passwd	 pw, *res;
	char		 buf[1024];
	gid_t		 groups[64];
	int		 n = sizeof(groups) / sizeof(groups[0]);

	if (opts.sock_gid == (gid_t)-1)
		return (false);
	if (gid == opts.sock_gid)
		return (true);
	if (getpwuid_r(uid, &pw, buf, sizeof(buf), &res) != 0 || res == NULL ||
	    getgrouplist(res->pw_name, res->pw_gid, groups, &n) == -1)
		return (false);
	for (int i = 0; i < n; i++)
		if (groups[i] == opts.sock_gid)
			return (true);
	return (false);
}

/*
 * What kind of peer p is: root or the agent's own user on the unix
 * socket (PEER_ROOT: the recovery session, which may install a program
 * unsigned); a local account in the socket's group (-g, the console's
 * user by the configuration: PEER_GROUP); another local account
 * (PEER_LOCAL); over TLS, the console by its certificate's role
 * (PEER_CONSOLE), another host by its own (PEER_HOST), anything else
 * nobody (PEER_NONE), as is a peer whose credentials are not known.
 * The uid of a local one in *uidp.
 */
enum peer_kind
peer_kind(const cbl_peer *p, uid_t *uidp)
{
	uid_t	uid;
	gid_t	gid;

	if (uidp != NULL)
		*uidp = (uid_t)-1;
	if (p == NULL)
		return (PEER_NONE);
	if (cbl_peer_transport(p) == CBL_TR_UNIX) {
		if (cbl_peer_cred(p, &uid, &gid) != 0)
			return (PEER_NONE);
		if (uidp != NULL)
			*uidp = uid;
		if (uid == 0 || uid == geteuid())
			return (PEER_ROOT);
		return (in_sock_group(uid, gid) ? PEER_GROUP : PEER_LOCAL);
	}
	if (has_role(p, ROLE_AGENT))
		return (PEER_HOST);
	return (has_role(p, ROLE_CONSOLE) ? PEER_CONSOLE : PEER_NONE);
}

/*
 * Whom a request of peer p is for (cbl_user_f), by peer_kind(): root's
 * the user it says or the recovery session; the socket's group's and
 * the console's the user it says or "console"; another local
 * account's "local:<login>".  A host's certificate, and one without
 * the console's role, ask nothing.
 */
static int
admit_user(const cbl_peer *p, const char *said, char *name, size_t len,
    bool *recovery, void *arg __unused)
{
	struct passwd	 pw, *res;
	char		 buf[1024];
	uid_t		 uid;

	switch (peer_kind(p, &uid)) {
	case PEER_ROOT:
		if (said != NULL)
			(void)strlcpy(name, said, len);
		else
			*recovery = true;
		return (0);
	case PEER_GROUP:
	case PEER_CONSOLE:
		(void)strlcpy(name, said != NULL ? said : NACM_CONSOLE, len);
		return (0);
	case PEER_LOCAL:
		if (said != NULL)
			return (EACCES);
		/* A name of its own: a local account called admin is not
		 * the console's admin. */
		if (getpwuid_r(uid, &pw, buf, sizeof(buf), &res) == 0 &&
		    res != NULL)
			(void)snprintf(name, len, "local:%s", res->pw_name);
		else
			(void)snprintf(name, len, "local:%u", (unsigned)uid);
		return (0);
	case PEER_HOST:
		logmsg(LOG_WARNING, "%s: a host's certificate asked: refused, "
		    "only the console asks", cbl_peer_subject(p) != NULL ?
		    cbl_peer_subject(p) : "?");
		return (EACCES);
	case PEER_NONE:
		break;
	}
	if (p != NULL && cbl_peer_transport(p) != CBL_TR_UNIX)
		logmsg(LOG_WARNING, "%s: a certificate without the console's "
		    "role (urn:arcana:role:console) asked: refused; the "
		    "console issues itself one with it when it starts "
		    "(docs/UPDATING.md)", cbl_peer_subject(p) != NULL ?
		    cbl_peer_subject(p) : "?");
	return (EACCES);
}

/* Whom each request is for, admit_user()'s, for NACM; before any
 * family is registered. */
int
admit_init(cbl_ctx *ctx)
{

	return (cbl_ctx_set_user(ctx, admit_user, NULL));
}

/* ---- arcana-stream: the streams' family ------------------------------ */

typedef int	open_f(cbl_req *, const struct arcana_stream_open *,
		    cbl_stream *);

/* A stream's opening: its open structure, to the command's handler. */
static int
stream_opened(cbl_req *req, const cbl_msg *msg, cbl_stream *s, open_f *fn)
{
	struct arcana_stream_open	 in;
	cbl_yarena			*a;
	char				 why[256];
	int				 error;

	/* The console's alone; admit_user() refuses a host too, before
	 * NACM. */
	if (peer_is_host(cbl_req_peer(req))) {
		(void)cbl_req_set_err(req, "only the console may open this "
		    "stream", NULL, 0, -1);
		return (EPERM);
	}
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	memset(&in, 0, sizeof(in));
	if (arcana_stream_open_parse(msg, &in, a, CBL_YD_STRICT, why,
	    sizeof(why)) != 0) {
		(void)cbl_req_set_err(req, why, NULL, 0, -1);
		cbl_yarena_free(a);
		return (EINVAL);
	}
	error = fn(req, &in, s);
	cbl_yarena_free(a);
	return (error);
}

static int
zfs_send_sopen(cbl_req *req, const cbl_msg *msg, cbl_stream *s,
    void *arg __unused)
{

	return (stream_opened(req, msg, s, zfs_send_open));
}

static int
zfs_receive_sopen(cbl_req *req, const cbl_msg *msg, cbl_stream *s,
    void *arg __unused)
{

	return (stream_opened(req, msg, s, zfs_receive_open));
}

static int
pcap_put_sopen(cbl_req *req, const cbl_msg *msg, cbl_stream *s,
    void *arg __unused)
{

	return (stream_opened(req, msg, s, pcap_put_open));
}

static int
pcap_get_sopen(cbl_req *req, const cbl_msg *msg, cbl_stream *s,
    void *arg __unused)
{

	return (stream_opened(req, msg, s, pcap_get_open));
}

/*
 * Each gives out a dataset or a capture, or writes them: NACM's to let
 * through, by its name, and refused to any other unless a rule says.
 */
#define	STREAM_OPF	(CBL_OPF_STREAM | CBL_OPF_AUTH | CBL_OPF_NACM | \
	CBL_OPF_DENY)

static int
exec_follow_sopen(cbl_req *req, const cbl_msg *msg, cbl_stream *s,
    void *arg __unused)
{

	return (stream_opened(req, msg, s, exec_follow_open));
}

static const struct cbl_op stream_ops[] = {
	{ .cmd = YS_ZFS_SEND, .flags = STREAM_OPF, .name = "zfs-send",
	    .stream_open = zfs_send_sopen },
	{ .cmd = YS_ZFS_RECEIVE, .flags = STREAM_OPF, .name = "zfs-receive",
	    .stream_open = zfs_receive_sopen },
	{ .cmd = YS_PCAP_PUT, .flags = STREAM_OPF,
	    .name = "suricata-pcap-put", .stream_open = pcap_put_sopen },
	{ .cmd = YS_PCAP_GET, .flags = STREAM_OPF,
	    .name = "suricata-pcap-get", .stream_open = pcap_get_sopen },
	/* A job's program as it runs: read as its trace is, by every
	 * role, NACM's default unless a rule says. */
	{ .cmd = YS_EXEC_FOLLOW, .flags = CBL_OPF_STREAM | CBL_OPF_AUTH |
	    CBL_OPF_NACM, .name = "exec-follow",
	    .stream_open = exec_follow_sopen },
};

static const struct cbl_family_def stream_def = {
	.abi = CBL_FAMILY_ABI,
	.name = YS_FAMILY_NAME,
	.version = 1,
	.ops = stream_ops,
	.nops = nitems(stream_ops),
};

int
stream_register(cbl_ctx *ctx)
{
	cbl_family	*fam;

	return (cbl_family_register(ctx, &stream_def, NULL, &fam));
}
