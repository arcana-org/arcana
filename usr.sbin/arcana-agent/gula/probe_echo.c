/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Gula, an echo told to its target: the host's echo replies come in on
 * a socket a FIB and a family (probe_icmp.c), every target's, and are
 * told to the target by the echo's id, then to the probe in the air by
 * its sequence.  The ids are each family's own among the live targets
 * (probe.c's ident_alloc()), kept sorted here as the table is made at
 * each change of the targets, so a reply is found its target by a
 * search, not a walk; a reply whose id no target has (another program's
 * ping, a target gone) is passed over, as is one whose sequence is in
 * the air no more (late, or twice).  Nothing here but the arithmetic:
 * the prober's sockets and clock are its callers'.
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "agent.h"
#include "stamp.h"
#include "probe_int.h"

void
echo_ids_clear(struct echo_ids *e)
{

	e->n = 0;
}

/* Target idx's id, of family af; TARGETS_MAX at most. */
void
echo_ids_add(struct echo_ids *e, int af, uint16_t id, int idx)
{

	if (e->n == TARGETS_MAX)
		return;
	e->v[e->n].id = id;
	e->v[e->n].af = (uint8_t)af;
	e->v[e->n++].idx = idx;
}

static int
echo_cmp(const void *a, const void *b)
{
	const struct echo_id	*x = a, *y = b;

	if (x->af != y->af)
		return (x->af < y->af ? -1 : 1);
	return (x->id < y->id ? -1 : x->id > y->id);
}

void
echo_ids_sort(struct echo_ids *e)
{

	qsort(e->v, (size_t)e->n, sizeof(e->v[0]), echo_cmp);
}

/* The target of an echo id of family af, or -1. */
int
echo_ids_find(const struct echo_ids *e, int af, uint16_t id)
{
	int	lo, hi, mid;

	lo = 0;
	hi = e->n - 1;
	while (lo <= hi) {
		mid = (lo + hi) / 2;
		if (e->v[mid].af == af && e->v[mid].id == id)
			return (e->v[mid].idx);
		if (e->v[mid].af < af || (e->v[mid].af == af &&
		    e->v[mid].id < id))
			lo = mid + 1;
		else
			hi = mid - 1;
	}
	return (-1);
}

/*
 * A packet read from a raw socket of family af (n bytes; IPv4's with its
 * header, IPv6's without, as the kernel hands them): an echo reply's id
 * and sequence, 0; -1 for anything else.
 */
int
echo_parse(int af, const unsigned char *pkt, size_t n, uint16_t *id,
    uint16_t *seq)
{

	if (af == AF_INET) {
		const struct ip		*ip = (const struct ip *)(const void *)pkt;
		const struct icmp	*ic;
		size_t			 hl;

		if (n < sizeof(*ip))
			return (-1);
		hl = (size_t)ip->ip_hl << 2;
		if (n < hl + ICMP_MINLEN)
			return (-1);
		ic = (const struct icmp *)(const void *)(pkt + hl);
		if (ic->icmp_type != ICMP_ECHOREPLY)
			return (-1);
		*id = ntohs(ic->icmp_id);
		*seq = ntohs(ic->icmp_seq);
	} else {
		const struct icmp6_hdr	*ic = (const struct icmp6_hdr *)
		    (const void *)pkt;

		if (n < sizeof(*ic) || ic->icmp6_type != ICMP6_ECHO_REPLY)
			return (-1);
		*id = ntohs(ic->icmp6_id);
		*seq = ntohs(ic->icmp6_seq);
	}
	return (0);
}

/* A slot for a probe to send: a free one, else the oldest in the air
 * (full, its probe given up). */
int
echo_slot(struct echo_out *out, int n, bool *full)
{
	int	i, slot;

	*full = false;
	for (i = 0; i < n; i++)
		if (!out[i].live)
			return (i);
	slot = 0;
	for (i = 1; i < n; i++)
		if (out[i].sent < out[slot].sent)
			slot = i;
	*full = true;
	return (slot);
}

/* The probe of sequence seq in the air, taken (no longer live): its
 * slot, or -1 when none is (late, or answered already). */
int
echo_take(struct echo_out *out, int n, uint16_t seq)
{
	int	i;

	for (i = 0; i < n; i++)
		if (out[i].live && out[i].seq == seq) {
			out[i].live = false;
			return (i);
		}
	return (-1);
}
