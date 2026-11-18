/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef _OPRULES_H_
#define	_OPRULES_H_

#include <stdbool.h>

/*
 * The rule-list operator of a host's access rules: what the console's
 * operators of the host may that the host keeps nacm:default-deny-all,
 * the same in the console's nacm-sync (ytrans.c) and the agent's
 * default rules (ynacm.c), so that a fresh host and a synchronized one
 * are one.  arcana-system's read (exec: the system's files, keys among
 * them); BIRD's texts and services' values (read: a viewer has them
 * not).  Each a rule's name, its module, its path and whether it is an
 * exec's or a read's permit.
 */
#define	OP_RULES { \
	{ "system-read", "arcana-system", "/arcana-system:system/read", \
	    true, "The console's operators read the system's files.", NULL }, \
	{ "bird-text", "arcana-bird", \
	    "/arcana-bird:bird/configuration/file/text", false, \
	    "The console's operators read what holds secrets, its viewers " \
	    "not.", NULL }, \
	{ "bird-jail-text", "arcana-bird", \
	    "/arcana-bird:bird/jail/configuration/file/text", false, \
	    "The console's operators read what holds secrets, its viewers " \
	    "not.", NULL }, \
	{ "service-values", "arcana-services", \
	    "/arcana-services:services/service/variable/value", false, \
	    "The console's operators read what holds secrets, its viewers " \
	    "not.", NULL }, \
	{ "terminal", "arcana-stream", NULL, true, \
	    "The console's operators open a terminal (login asks the " \
	    "password).", "terminal" }, \
	{ "terminal-as", "arcana-stream", NULL, true, \
	    "The console's operators open a mapped login, as the host's " \
	    "terminal-users allows it.", "terminal-as" }, \
}

/*
 * Who the console says an API token that reads is (its hosts.c): a name
 * no user of the console has, in no group, whom an agent holds to a
 * viewer's reads whatever its rules say (clearance()); the console's
 * nacm-sync takes it out of every group.
 */
#define	NACM_TOKEN_READ	"token-read"

struct op_rule {
	const char	*name, *module, *path;
	bool		 exec;
	const char	*comment;
	const char	*rpc;
};

#endif /* !_OPRULES_H_ */
