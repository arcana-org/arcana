/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * ynacmw: access rules (ietf-netconf-acm) as the agent's --nacm file
 * has them, YANG-CBOR, for agent_test.sh: rules an EDIT would refuse
 * now, as a host may have kept from before.
 *
 *	ynacmw file group action module path
 *			group admin (users admin and console) permitted
 *			all; group with the user of the same name, and one
 *			rule-list of it, a data rule for every access of
 *			module (or "*") and path, permit or deny
 *	ynacmw -c	whether every path of the rules the agent writes
 *			itself (the shared OP_RULES) compiles for its
 *			schema: "ok name" or "bad name: why", a line each
 */

#include <sys/param.h>

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cblink.h>
#include <cbl_data.h>
#include <cbl_schema.h>

#include "oprules.h"
#include "ymodel.h"

static const struct op_rule	op_rules[] = OP_RULES;

static const struct cbl_ynode *
nacm_node(void)
{

	for (uint32_t i = 0; i < ymodel_schema.nmod; i++) {
		const struct cbl_ymodule *m = ymodel_schema.mod[i];

		if (strcmp(m->name, "ietf-netconf-acm") != 0)
			continue;
		for (uint32_t j = 0; j < m->ntop; j++)
			if (strcmp(m->top[j]->name, "nacm") == 0)
				return (m->top[j]);
	}
	errx(1, "no ietf-netconf-acm:nacm in the tables");
}

static int
check(void)
{
	cbl_dnacm_path *p;
	char why[160];
	int bad = 0;

	for (size_t i = 0; i < nitems(op_rules); i++) {
		/* An operation's rule has no path. */
		if (op_rules[i].path == NULL) {
			printf("ok %s\n", op_rules[i].name);
			continue;
		}
		if ((p = cbl_dnacm_path_new(&ymodel_schema, op_rules[i].path,
		    why, sizeof(why))) == NULL) {
			printf("bad %s: %s\n", op_rules[i].name, why);
			bad = 1;
			continue;
		}
		cbl_dnacm_path_free(p);
		printf("ok %s\n", op_rules[i].name);
	}
	return (bad);
}

int
main(int argc, char **argv)
{
	static const char *const admins[] = { "admin", "console" };
	struct ietf_netconf_acm_nacm_groups_group g[2];
	struct ietf_netconf_acm_nacm_groups gs;
	struct ietf_netconf_acm_nacm_rule_list_group lg[2];
	struct ietf_netconf_acm_nacm_rule_list_rule r[2];
	struct ietf_netconf_acm_nacm_rule_list l[2];
	struct ietf_netconf_acm_nacm n;
	struct ietf_netconf_acm d;
	struct cbl_ybuf b = { NULL, 0, 0 };
	const char *user;
	int fd;

	if (argc == 2 && strcmp(argv[1], "-c") == 0)
		return (check());
	if (argc != 6)
		errx(2, "usage: ynacmw file group permit|deny module path");
	user = argv[2];
	memset(g, 0, sizeof(g));
	memset(lg, 0, sizeof(lg));
	memset(r, 0, sizeof(r));
	memset(l, 0, sizeof(l));
	memset(&n, 0, sizeof(n));
	memset(&gs, 0, sizeof(gs));
	g[0].name = "admin";
	g[0].user_name.n = 2;
	g[0].user_name.v = admins;
	g[1].name = argv[2];
	g[1].user_name.n = 1;
	g[1].user_name.v = &user;
	gs.group.n = 2;
	gs.group.v = g;
	lg[0].which = lg[1].which = 1;
	lg[0].v.m1 = "admin";
	lg[1].v.m1 = argv[2];
	r[0].name = "permit-all";
	r[0].has_module_name = true;
	r[0].module_name.which = 0;
	r[0].module_name.v.m0 = "*";
	r[0].has_access_operations = true;
	r[0].access_operations.which = 0;
	r[0].access_operations.v.m0 = "*";
	r[0].has_action = true;
	r[0].action = IETF_NETCONF_ACM_NACM_RULE_LIST_RULE_ACTION_PERMIT;
	r[1].name = "kept";
	r[1].has_module_name = true;
	if (strcmp(argv[4], "*") == 0) {
		r[1].module_name.which = 0;
		r[1].module_name.v.m0 = "*";
	} else {
		r[1].module_name.which = 1;
		r[1].module_name.v.m1 = argv[4];
	}
	r[1].rule_type =
	    IETF_NETCONF_ACM_NACM_RULE_LIST_RULE_RULE_TYPE_DATA_NODE;
	r[1].path = argv[5];
	r[1].has_access_operations = true;
	r[1].access_operations.which = 0;
	r[1].access_operations.v.m0 = "*";
	r[1].has_action = true;
	r[1].action = strcmp(argv[3], "permit") == 0 ?
	    IETF_NETCONF_ACM_NACM_RULE_LIST_RULE_ACTION_PERMIT :
	    IETF_NETCONF_ACM_NACM_RULE_LIST_RULE_ACTION_DENY;
	l[0].name = "admin";
	l[0].group.n = 1;
	l[0].group.v = &lg[0];
	l[0].rule.n = 1;
	l[0].rule.v = &r[0];
	l[1].name = argv[2];
	l[1].group.n = 1;
	l[1].group.v = &lg[1];
	l[1].rule.n = 1;
	l[1].rule.v = &r[1];
	n.has_enable_nacm = true;
	n.enable_nacm = true;
	n.groups = &gs;
	n.rule_list.n = 2;
	n.rule_list.v = l;
	memset(&d, 0, sizeof(d));
	d.nacm = &n;
	if (cbl_yencode_member(nacm_node(), &d, &b) != 0)
		errx(1, "the rules not encoded");
	if ((fd = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC, 0600)) == -1)
		err(1, "%s", argv[1]);
	if (write(fd, b.p, b.len) != (ssize_t)b.len)
		err(1, "%s", argv[1]);
	(void)close(fd);
	cbl_ybuf_free(&b);
	return (0);
}
