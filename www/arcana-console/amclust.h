/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef AMCLUST_H
#define	AMCLUST_H

#include <stddef.h>

#include <ucl.h>

/* RFC 9342 §5.1's partition: each arc's cluster, from 0 in the order of
 * the arcs; how many clusters. */
int		 am_partition(size_t, const char *const *, const char *const *,
		    int *);
/* The loss of each tunnel's each way by block, and the clusters, of the
 * plan's tunnels and the edges' blocks (amclust.c). */
ucl_object_t	*am_view(const ucl_object_t *, const ucl_object_t *);
/* A rule's dscp list, each class and its coloured neighbour. */
const char	*am_dscp_widen(const char *, char *, size_t);

#endif
