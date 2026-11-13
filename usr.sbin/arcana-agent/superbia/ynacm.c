/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Superbia's rules: ietf-netconf-acm's nacm (RFC 8341), which cblink
 * checks every request against.  They are kept in a file of their own,
 * --nacm, as YANG-CBOR, written whole by an EDIT through family 1 (which
 * the rules themselves let the admin alone make: the container is
 * nacm:default-deny-all).  Without the file, the default: the console's
 * admin, and the console for the requests it makes for nobody, in group
 * admin, whose rule-list permits everything; for anyone else RFC 8341's
 * defaults, reads and rpcs permitted, writes not, nor what is marked
 * nacm:default-deny-all or -write.  Deleting the rules brings the
 * default back.  A file that cannot be read denies everything but the
 * recovery session (root, or the agent's own user, on the unix socket),
 * which can write it anew.  How far a request is trusted by its groups
 * (clearance()) also decides what a read runs: a vnet jail's own
 * program, by jexec, for an operator and above (jail_prog_refused()).
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "agent.h"
#include "oprules.h"
#include "ymodel.h"

#define	NACM_FILE_MAX	(1024 * 1024)

static pthread_mutex_t	nacm_lock = PTHREAD_MUTEX_INITIALIZER;

static const struct cbl_ynode *
nacm_node(void)
{

	return (ynode_named("ietf-netconf-acm", "nacm"));
}

static const uint8_t		op_exec[] = {
	1u << IETF_NETCONF_ACM_NACM_RULE_LIST_RULE_ACCESS_OPERATIONS_M1_EXEC
};
static const uint8_t		op_read[] = {
	1u << IETF_NETCONF_ACM_NACM_RULE_LIST_RULE_ACCESS_OPERATIONS_M1_READ
};
static const struct op_rule	op_rules[] = OP_RULES;

/*
 * The default rules, in a: group admin as the head says; group
 * operator, empty until the console's nacm-sync fills it, and its
 * rule-list exactly as the console's sync writes it (oprules.h), so a
 * fresh host and a synchronized one are one.
 */
static struct ietf_netconf_acm_nacm *
nacm_default(cbl_yarena *a)
{
	struct ietf_netconf_acm_nacm_groups_group	*g;
	struct ietf_netconf_acm_nacm_groups		*gs;
	struct ietf_netconf_acm_nacm_rule_list_group	*lg, *olg;
	struct ietf_netconf_acm_nacm_rule_list_rule	*r, *or;
	struct ietf_netconf_acm_nacm_rule_list		*l;
	struct ietf_netconf_acm_nacm			*n;
	const char					**users;
	size_t						 i;

	if ((g = cbl_yarena_alloc(a, 2 * sizeof(*g))) == NULL ||
	    (l = cbl_yarena_alloc(a, 2 * sizeof(*l))) == NULL ||
	    (olg = cbl_yarena_alloc(a, sizeof(*olg))) == NULL ||
	    (or = cbl_yarena_alloc(a, nitems(op_rules) * sizeof(*or))) == NULL)
		return (NULL);
	memset(g, 0, 2 * sizeof(*g));
	memset(l, 0, 2 * sizeof(*l));
	memset(or, 0, nitems(op_rules) * sizeof(*or));
	g[1].name = NACM_OPERATOR;
	olg->which = 1;
	olg->v.m1 = NACM_OPERATOR;
	for (i = 0; i < nitems(op_rules); i++) {
		or[i].name = op_rules[i].name;
		or[i].has_module_name = true;
		or[i].module_name.which = 1;
		or[i].module_name.v.m1 = op_rules[i].module;
		or[i].rule_type =
		    IETF_NETCONF_ACM_NACM_RULE_LIST_RULE_RULE_TYPE_DATA_NODE;
		or[i].path = op_rules[i].path;
		or[i].has_access_operations = true;
		or[i].access_operations.which = 1;
		or[i].access_operations.v.m1.p = op_rules[i].exec ? op_exec :
		    op_read;
		or[i].access_operations.v.m1.len = 1;
		or[i].has_action = true;
		or[i].action = IETF_NETCONF_ACM_NACM_RULE_LIST_RULE_ACTION_PERMIT;
		or[i].comment = op_rules[i].comment;
	}
	l[1].name = NACM_OPERATOR;
	l[1].group.n = 1;
	l[1].group.v = olg;
	l[1].rule.n = nitems(op_rules);
	l[1].rule.v = or;
	if ((n = cbl_yarena_alloc(a, sizeof(*n))) == NULL ||
	    (gs = cbl_yarena_alloc(a, sizeof(*gs))) == NULL ||
	    (users = cbl_yarena_alloc(a, 2 * sizeof(*users))) == NULL ||
	    (lg = cbl_yarena_alloc(a, sizeof(*lg))) == NULL ||
	    (r = cbl_yarena_alloc(a, sizeof(*r))) == NULL)
		return (NULL);
	users[0] = NACM_ADMIN;
	users[1] = NACM_CONSOLE;
	g->name = "admin";
	g->user_name.n = 2;
	g->user_name.v = users;
	gs->group.n = 2;
	gs->group.v = g;
	lg->which = 1;
	lg->v.m1 = "admin";
	r->name = "permit-all";
	r->has_module_name = true;
	r->module_name.which = 0;
	r->module_name.v.m0 = "*";
	r->has_access_operations = true;
	r->access_operations.which = 0;
	r->access_operations.v.m0 = "*";
	r->has_action = true;
	r->action = IETF_NETCONF_ACM_NACM_RULE_LIST_RULE_ACTION_PERMIT;
	r->comment = "The console's admin, and the console, may do anything.";
	l->name = "admin";
	l->group.n = 1;
	l->group.v = lg;
	l->rule.n = 1;
	l->rule.v = r;
	n->has_enable_nacm = true;
	n->enable_nacm = true;
	n->has_read_default = true;
	n->read_default = IETF_NETCONF_ACM_NACM_READ_DEFAULT_PERMIT;
	n->has_write_default = true;
	n->write_default = IETF_NETCONF_ACM_NACM_WRITE_DEFAULT_DENY;
	n->has_exec_default = true;
	n->exec_default = IETF_NETCONF_ACM_NACM_EXEC_DEFAULT_PERMIT;
	n->groups = gs;
	n->rule_list.n = 2;
	n->rule_list.v = l;
	return (n);
}

/* The file's text, malloc'd; NULL and ENOENT where there is none. */
static uint8_t *
nacm_read(size_t *lenp)
{
	struct stat	 sb;
	uint8_t		*p;
	ssize_t		 n;
	int		 fd;

	if ((fd = open(opts.nacm_file, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)) ==
	    -1)
		return (NULL);
	if (fstat(fd, &sb) != 0 || !S_ISREG(sb.st_mode) || sb.st_size <= 0 ||
	    sb.st_size > NACM_FILE_MAX || (p = malloc((size_t)sb.st_size)) ==
	    NULL) {
		(void)close(fd);
		errno = EIO;
		return (NULL);
	}
	if ((n = read(fd, p, (size_t)sb.st_size)) != sb.st_size) {
		free(p);
		(void)close(fd);
		errno = EIO;
		return (NULL);
	}
	(void)close(fd);
	*lenp = (size_t)n;
	return (p);
}

int
ietf_netconf_acm_nacm_get(cbl_req *req, struct ietf_netconf_acm *data,
    cbl_yarena *a)
{
	struct ietf_netconf_acm_nacm	*n;
	struct cbl_ynacm_counts		 c;
	uint8_t				*p;
	size_t				 len;
	char				 why[160];
	int				 error;

	pthread_mutex_lock(&nacm_lock);
	p = nacm_read(&len);
	pthread_mutex_unlock(&nacm_lock);
	if (p == NULL && errno != ENOENT) {
		logmsg(LOG_ERR, "%s: cannot be read: only root on the unix "
		    "socket may ask anything", opts.nacm_file);
		return (EIO);
	}
	if (p != NULL) {
		error = cbl_ydecode_member(nacm_node(), p, len, data, a,
		    CBL_YD_STRICT, why, sizeof(why));
		free(p);
		if (error != 0) {
			logmsg(LOG_ERR, "%s: %s: only root on the unix socket "
			    "may ask anything", opts.nacm_file, why);
			return (EIO);
		}
	}
	/* A copy, the counters of cblink's in it. */
	if (data->nacm == NULL)
		n = nacm_default(a);
	else if ((n = cbl_yarena_alloc(a, sizeof(*n))) != NULL)
		*n = *data->nacm;
	if (n == NULL)
		return (ENOMEM);
	cbl_ynacm_counters(cbl_req_ctx(req), &c);
	n->has_denied_operations = true;
	n->denied_operations = c.denied_operations;
	n->has_denied_data_writes = true;
	n->denied_data_writes = c.denied_data_writes;
	n->has_denied_notifications = true;
	n->denied_notifications = c.denied_notifications;
	data->nacm = n;
	return (0);
}

/* The rules written whole, in place of the file; none: the file gone, the
 * default back. */
int
ietf_netconf_acm_nacm_edit(cbl_req *req, const struct ietf_netconf_acm *before,
    const struct ietf_netconf_acm *after)
{
	struct cbl_ybuf	 b = { NULL, 0, 0 };
	char		 tmp[PATH_MAX];
	int		 error, fd;

	(void)req;
	(void)before;
	pthread_mutex_lock(&nacm_lock);
	if (after->nacm == NULL) {
		error = unlink(opts.nacm_file) == 0 || errno == ENOENT ? 0 :
		    errno;
		pthread_mutex_unlock(&nacm_lock);
		return (error);
	}
	if ((error = cbl_yencode_member(nacm_node(), after, &b)) != 0) {
		pthread_mutex_unlock(&nacm_lock);
		return (error);
	}
	(void)snprintf(tmp, sizeof(tmp), "%s.arcana-new", opts.nacm_file);
	error = 0;
	if ((fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC |
	    O_NOFOLLOW, 0600)) == -1)
		error = errno;
	else {
		if (write(fd, b.p, b.len) != (ssize_t)b.len || fsync(fd) != 0)
			error = errno != 0 ? errno : EIO;
		if (close(fd) != 0 && error == 0)
			error = errno;
		if (error == 0 && rename(tmp, opts.nacm_file) != 0)
			error = errno;
		if (error != 0)
			(void)unlink(tmp);
	}
	pthread_mutex_unlock(&nacm_lock);
	cbl_ybuf_free(&b);
	if (error == 0)
		logmsg(LOG_NOTICE, "%s: the access rules written",
		    opts.nacm_file);
	return (error);
}

/*
 * How far the request's user is trusted with what a read gives out
 * (agent.h): the recovery session, and a user of group admin, an
 * admin's; of group operator, an operator's; anyone else, and anyone
 * while the rules cannot be read, a viewer's.  The console's read
 * tokens (NACM_TOKEN_READ, no user's name) a viewer's whatever group
 * the rules put it in.
 */
int
clearance(cbl_req *req)
{
	const struct ietf_netconf_acm_nacm_groups	*gs;
	const struct ietf_netconf_acm_nacm		*n;
	struct ietf_netconf_acm				 d;
	const char					*user;
	cbl_yarena					*a;
	uint8_t						*p;
	size_t						 len, i, k;
	char						 why[160];
	int						 c;

	if ((user = cbl_req_user(req)) == NULL)
		return (CLEAR_ADMIN);
	if (strcmp(user, NACM_TOKEN_READ) == 0)
		return (CLEAR_VIEWER);
	if ((a = cbl_yarena_new()) == NULL)
		return (CLEAR_VIEWER);
	pthread_mutex_lock(&nacm_lock);
	p = nacm_read(&len);
	pthread_mutex_unlock(&nacm_lock);
	memset(&d, 0, sizeof(d));
	n = NULL;
	if (p == NULL && errno == ENOENT)
		n = nacm_default(a);
	else if (p != NULL && cbl_ydecode_member(nacm_node(), p, len, &d, a,
	    CBL_YD_STRICT, why, sizeof(why)) == 0)
		n = d.nacm != NULL ? d.nacm : nacm_default(a);
	free(p);
	c = CLEAR_VIEWER;
	if (n != NULL && (gs = n->groups) != NULL)
		for (i = 0; i < gs->group.n; i++)
			for (k = 0; k < gs->group.v[i].user_name.n; k++) {
				if (strcmp(gs->group.v[i].user_name.v[k], user) !=
				    0)
					continue;
				if (strcmp(gs->group.v[i].name, NACM_ADMIN) == 0)
					c = CLEAR_ADMIN;
				else if (strcmp(gs->group.v[i].name,
				    NACM_OPERATOR) == 0 && c < CLEAR_OPERATOR)
					c = CLEAR_OPERATOR;
			}
	cbl_yarena_free(a);
	return (c);
}

/*
 * A read that runs a vnet jail's own program in it (jexec(8): the
 * jail's ipfw, birdc, wg, swanctl, sysctl or ifmcstat, whatever the
 * jail put at that path) is run for an operator and above: a viewer's
 * request runs nothing a jail controls, and nothing of it is collected
 * for one.  NULL when it may run (no jail: the host's own fixed tool),
 * else why not, into buf.
 */
const char *
jail_prog_refused(cbl_req *req, const char *jail, const char *prog,
    char *buf, size_t len)
{

	if (jail == NULL || jail[0] == '\0' || clearance(req) >=
	    CLEAR_OPERATOR)
		return (NULL);
	(void)snprintf(buf, len, "%s in the jail %s is the jail's own "
	    "program, run there as its root: read by an operator of the "
	    "host, not a viewer", prog, jail);
	return (buf);
}
