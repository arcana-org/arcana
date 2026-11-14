/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * echoid: gula/probe_echo.c alone, for agent_test.sh: an echo reply told
 * to its target by its id and to its probe by its sequence.  Each line
 * printed is what came of one question:
 *
 *	find AF ID	the target of an echo id (-1 none)
 *	take SEQ	the slot of a probe in the air taken (-1 none)
 *	slot		a slot for a probe to send (full: the oldest)
 *	parse WHAT	a packet read as an echo reply: its id and sequence
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
#include <stdio.h>
#include <string.h>

#include "agent.h"
#include "stamp.h"
#include "probe_int.h"

static struct echo_ids	ids;

static const char *
afname(int af)
{

	return (af == AF_INET ? "inet" : "inet6");
}

static void
find(int af, uint16_t id)
{

	printf("find %s %u %d\n", afname(af), id, echo_ids_find(&ids, af, id));
}

/* The table: the targets 0 to 3, then again without target 2 (gone). */
static void
t_ids(void)
{

	echo_ids_clear(&ids);
	echo_ids_add(&ids, AF_INET, 7, 0);
	echo_ids_add(&ids, AF_INET6, 7, 1);
	echo_ids_add(&ids, AF_INET, 65535, 2);
	echo_ids_add(&ids, AF_INET, 1, 3);
	echo_ids_sort(&ids);
	find(AF_INET, 7);
	find(AF_INET6, 7);
	find(AF_INET, 65535);
	find(AF_INET, 1);
	/* Another program's ping, another family's id. */
	find(AF_INET, 8);
	find(AF_INET6, 65535);
	/* Target 2 gone: its replies are no one's. */
	echo_ids_clear(&ids);
	echo_ids_add(&ids, AF_INET, 7, 0);
	echo_ids_add(&ids, AF_INET6, 7, 1);
	echo_ids_add(&ids, AF_INET, 1, 2);
	echo_ids_sort(&ids);
	find(AF_INET, 65535);
	find(AF_INET, 1);
}

/* A target's probes in the air over the sequence's wrap: each taken
 * once, a reply again or for none sent passed over; a full window gives
 * its oldest. */
static void
t_seq(void)
{
	struct echo_out	out[4];
	uint16_t	seqs[] = { 65534, 65535, 0, 1 };
	bool		full;
	int		i, s;

	memset(out, 0, sizeof(out));
	for (i = 0; i < 4; i++) {
		s = echo_slot(out, 4, &full);
		out[s].seq = seqs[i];
		out[s].sent = 10.0 + i;
		out[s].live = true;
		printf("slot %d%s\n", s, full ? " full" : "");
	}
	printf("take 0 %d\n", echo_take(out, 4, 0));
	printf("take 65535 %d\n", echo_take(out, 4, 65535));
	printf("take 0 %d\n", echo_take(out, 4, 0));
	printf("take 2 %d\n", echo_take(out, 4, 2));
	/* Two free again: the first of them; then full, the oldest. */
	s = echo_slot(out, 4, &full);
	printf("slot %d%s\n", s, full ? " full" : "");
	out[1].live = out[2].live = true;
	out[1].sent = 13.5;
	out[2].sent = 9.5;
	s = echo_slot(out, 4, &full);
	printf("slot %d%s\n", s, full ? " full" : "");
}

static void
parse(const char *what, int af, const unsigned char *p, size_t n)
{
	uint16_t	id, seq;

	if (echo_parse(af, p, n, &id, &seq) != 0)
		printf("parse %s none\n", what);
	else
		printf("parse %s %u %u\n", what, id, seq);
}

/* Packets as a raw socket hands them: IPv4's with its header (here one
 * with options), IPv6's without. */
static void
t_parse(void)
{
	unsigned char		 pkt[64];
	struct ip		*ip = (struct ip *)(void *)pkt;
	struct icmp		*ic;
	struct icmp6_hdr	*ic6 = (struct icmp6_hdr *)(void *)pkt;

	memset(pkt, 0, sizeof(pkt));
	ip->ip_v = 4;
	ip->ip_hl = 6;
	ic = (struct icmp *)(void *)(pkt + 24);
	ic->icmp_type = ICMP_ECHOREPLY;
	ic->icmp_id = htons(4242);
	ic->icmp_seq = htons(65535);
	parse("reply4", AF_INET, pkt, 24 + ICMP_MINLEN);
	/* Our own request, seen on the loopback. */
	ic->icmp_type = ICMP_ECHO;
	parse("request4", AF_INET, pkt, 24 + ICMP_MINLEN);
	ic->icmp_type = ICMP_ECHOREPLY;
	parse("short4", AF_INET, pkt, 24 + ICMP_MINLEN - 1);
	memset(pkt, 0, sizeof(pkt));
	ic6->icmp6_type = ICMP6_ECHO_REPLY;
	ic6->icmp6_id = htons(7);
	ic6->icmp6_seq = htons(0);
	parse("reply6", AF_INET6, pkt, sizeof(*ic6));
	ic6->icmp6_type = ICMP6_ECHO_REQUEST;
	parse("request6", AF_INET6, pkt, sizeof(*ic6));
	ic6->icmp6_type = ICMP6_ECHO_REPLY;
	parse("short6", AF_INET6, pkt, sizeof(*ic6) - 1);
}

int
main(void)
{

	t_ids();
	t_seq();
	t_parse();
	return (0);
}
