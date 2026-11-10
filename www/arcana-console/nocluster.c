/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The console built without its cluster (WITHOUT_CLUSTER): nodes.c and
 * craft.c are left out, and this answers in their place as a console
 * that is not one of a cluster does.  Every document is written to the
 * data directory alone, every lock is this process's, and this node runs
 * the schedulers.  web.conf's cluster block stops the console: a node
 * that went on without it would take changes the others never see.
 * arcana-console:cluster answers 501, naming the build.
 */

#include "console.h"
#include "restconf.h"

int
cluster_config(const ucl_object_t *top, const char *path)
{

	if (ucl_object_lookup(top, "cluster") == NULL)
		return (0);
	log_msg(LOG_ERR, "%s: cluster: this arcana-console was built without "
	    "clustering (WITHOUT_CLUSTER)", path);
	return (-1);
}

int
cluster_init(void)
{

	return (0);
}

void
cluster_started(void)
{
}

bool
cluster_on(void)
{

	return (false);
}

bool
cluster_leads(void)
{

	return (true);
}

bool
cluster_origin(const char *o __unused)
{

	return (false);
}

bool
cluster_lock(const char *name __unused)
{

	return (true);
}

void
cluster_unlock(const char *name __unused)
{
}

uint64_t
cluster_gen(void)
{

	return (0);
}

int
cluster_save(const char *name, const void *body, size_t len, bool gone)
{

	return (gone ? store_remove(name) : store_write(name, body, len));
}

void
cluster_status(ucl_object_t *o)
{

	ucl_object_insert_key(o, ucl_object_frombool(false), "on", 0, false);
}

void
cluster_changes(void (*fn)(const char *) __unused)
{
}

int
api_cluster(struct http_request *req)
{

	if (!guard(req, false))
		return (WEB_OK);
	return (restconf_error_tag(req, 501, "operation-not-supported",
	    "this arcana-console was built without clustering "
	    "(WITHOUT_CLUSTER)"));
}
