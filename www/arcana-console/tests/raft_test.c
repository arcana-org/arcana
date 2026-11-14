/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The consoles' consensus (craft.c) in a simulated cluster: nodes with
 * disks of their own, a network that delays, drops and duplicates
 * messages and is cut in parts, nodes that crash and start again from
 * their disks, writes proposed to whoever leads, and the log compacted
 * so that some are sent the documents instead.  Raft's promises are
 * checked as it goes:
 *
 * - election safety: one leader at most a term;
 * - state machine safety: no two nodes apply different writes at one
 *   sequence;
 * - durability: a write the leader said was committed is applied, the
 *   same, by every node in the end;
 * - and, the network whole again, the cluster agrees: a leader, every
 *   node's documents alike;
 * - no two nodes hold a lease at once, and none from its election alone;
 * - what a node says it has kept (its term, its vote, its log) is what
 *   craft told it to keep before it said so.
 */

#include <atf-c.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../craft.h"

#define	NODES_MAX	5
#define	MSGS_MAX	20000
#define	DOCS_MAX	16
#define	SEQS_MAX	200000
#define	ACKS_MAX	20000

/* A message on the wire: its own copy of what it carries. */
struct wire {
	bool		 used;
	uint64_t	 at;		/* delivered then */
	int		 to;
	struct craft_msg m;
	/* a snapshot: the documents as the leader applied them */
	bool		 snap;
	char		 docs[DOCS_MAX][64];
	uint64_t	 snap_term, snap_seq;
};

struct disk {
	uint64_t		 term;
	char			 vote[CRAFT_NAME_MAX];
	uint64_t		 base_term, base_seq;
	struct craft_entry	*log;
	size_t			 nlog;
	char			 docs[DOCS_MAX][64];	/* the documents */
};

struct node {
	char		 name[CRAFT_NAME_MAX];
	bool		 up;
	struct craft	 c;
	struct disk	 d;
};

static struct node	 nodes[NODES_MAX];
static int		 nn;
static struct wire	*wires;
static uint64_t		 now;
static uint32_t		 seed;
static int		 part[NODES_MAX];	/* the side each is on */
static bool		 severed[NODES_MAX][NODES_MAX];	/* a link cut */
static double		 drop_p;
/* A node that stops between taking a message and keeping what it changed:
 * nothing of it said, nothing kept. */
static double		 crash_p;

/* seq -> what was applied there, by whoever applied it first. */
static struct {
	bool		 set;
	uint64_t	 term;
	char		 name[32];
	char		 body[64];
}			*applied;
static char		 leader_of_term[4096][CRAFT_NAME_MAX];
static struct {
	uint64_t	 term, seq;
	char		 name[32], body[64];
}			 acks[ACKS_MAX];
static int		 nacks;
/* Proposals waiting to be said committed. */
static struct {
	int		 node;
	uint64_t	 term, seq;
	char		 name[32], body[64];
	bool		 done;
}			 props[ACKS_MAX];
static int		 nprops;

static uint32_t
rnd(void)
{

	seed ^= seed << 13;
	seed ^= seed >> 17;
	seed ^= seed << 5;
	return (seed);
}

static int
node_of(const char *name)
{
	int	i;

	for (i = 0; i < nn; i++)
		if (strcmp(nodes[i].name, name) == 0)
			return (i);
	return (-1);
}

static void
entry_copy(struct craft_entry *to, const struct craft_entry *e)
{

	*to = *e;
	to->name = strdup(e->name);
	if (e->len > 0) {
		to->body = malloc(e->len);
		memcpy(to->body, e->body, e->len);
	} else
		to->body = NULL;
}

static void
entries_free(struct craft_entry *v, size_t n)
{
	size_t	i;

	for (i = 0; i < n; i++) {
		free(v[i].name);
		free(v[i].body);
	}
	free(v);
}

static void
send(int from, struct craft_msg *m)
{
	struct wire	*w;
	size_t		 i;
	int		 to, k, copies;

	if ((to = node_of(m->to)) < 0)
		return;
	copies = rnd() % 100 < 3 ? 2 : 1;	/* now and then twice */
	for (k = 0; k < copies; k++) {
		if ((double)(rnd() % 1000) / 1000.0 < drop_p)
			continue;
		if (part[from] != part[to] || severed[from][to])
			continue;
		for (i = 0; i < MSGS_MAX && wires[i].used; i++)
			;
		if (i == MSGS_MAX)
			return;
		w = &wires[i];
		memset(w, 0, sizeof(*w));
		w->used = true;
		w->to = to;
		w->at = now + 1 + rnd() % 40;
		w->m = *m;
		if (m->type == CRAFT_SNAPSHOT_NEEDED) {
			/* The documents as the sender applied them. */
			w->snap = true;
			memcpy(w->docs, nodes[from].d.docs, sizeof(w->docs));
			w->snap_term = m->last_term;
			w->snap_seq = m->last_seq;
			w->m.entries = NULL;
			w->m.nentries = 0;
		} else if (m->nentries > 0) {
			w->m.entries = calloc(m->nentries, sizeof(*m->entries));
			for (i = 0; i < m->nentries; i++)
				entry_copy(&w->m.entries[i], &m->entries[i]);
		}
	}
}

/* What a node's call left: kept on its disk, sent, applied. */
static void
after(int i)
{
	struct node		*n = &nodes[i];
	const struct craft_entry *e;
	size_t			 k;
	char			 body[64];
	int			 doc;

	/* What is not to be kept is kept already: a reply sent on the
	 * strength of a term, a vote or writes not on the disk would be
	 * forgotten by a crash after it. */
	if (!n->c.state_dirty)
		ATF_REQUIRE_MSG(n->d.term == n->c.term && strcmp(n->d.vote,
		    n->c.voted_for) == 0, "%s: term %ju vote %s, kept %ju %s, "
		    "not said to keep", n->name, (uintmax_t)n->c.term,
		    n->c.voted_for, (uintmax_t)n->d.term, n->d.vote);
	if (!n->c.log_truncated && n->c.log_dirty_from == 0)
		ATF_REQUIRE_MSG(n->d.nlog == n->c.nlog && n->d.base_seq ==
		    n->c.base_seq, "%s: log %ju+%zu, kept %ju+%zu, not said to "
		    "keep", n->name, (uintmax_t)n->c.base_seq, n->c.nlog,
		    (uintmax_t)n->d.base_seq, n->d.nlog);
	/* A leader's lease is none at its election: from answers alone. */
	if (n->c.role == CRAFT_LEADER && n->c.led_at == now)
		ATF_REQUIRE_MSG(!craft_quorum_heard(&n->c, CRAFT_LEASE_MS),
		    "%s holds a lease at its election, term %ju", n->name,
		    (uintmax_t)n->c.term);
	if (n->c.state_dirty) {
		n->d.term = n->c.term;
		strlcpy(n->d.vote, n->c.voted_for, sizeof(n->d.vote));
		n->c.state_dirty = false;
	}
	if (n->c.log_truncated || n->c.log_dirty_from != 0) {
		entries_free(n->d.log, n->d.nlog);
		n->d.log = calloc(n->c.nlog + 1, sizeof(*n->d.log));
		for (k = 0; k < n->c.nlog; k++)
			entry_copy(&n->d.log[k], &n->c.log[k]);
		n->d.nlog = n->c.nlog;
		n->d.base_term = n->c.base_term;
		n->d.base_seq = n->c.base_seq;
		n->c.log_truncated = false;
		n->c.log_dirty_from = 0;
	}
	if (n->c.role == CRAFT_LEADER) {
		ATF_REQUIRE(n->c.term < 4096);
		if (leader_of_term[n->c.term][0] == '\0')
			strlcpy(leader_of_term[n->c.term], n->name,
			    sizeof(leader_of_term[0]));
		else
			ATF_REQUIRE_MSG(strcmp(leader_of_term[n->c.term],
			    n->name) == 0, "two leaders in term %ju: %s and %s",
			    (uintmax_t)n->c.term, leader_of_term[n->c.term],
			    n->name);
	}
	for (k = 0; k < n->c.nout; k++)
		send(i, &n->c.out[k]);
	craft_out_clear(&n->c);
	while ((e = craft_next_apply(&n->c)) != NULL) {
		ATF_REQUIRE(e->seq < SEQS_MAX);
		snprintf(body, sizeof(body), "%.*s", (int)e->len,
		    e->body != NULL ? (const char *)e->body : "");
		if (!applied[e->seq].set) {
			applied[e->seq].set = true;
			applied[e->seq].term = e->term;
			strlcpy(applied[e->seq].name, e->name,
			    sizeof(applied[0].name));
			strlcpy(applied[e->seq].body, body,
			    sizeof(applied[0].body));
		} else
			ATF_REQUIRE_MSG(applied[e->seq].term == e->term &&
			    strcmp(applied[e->seq].name, e->name) == 0 &&
			    strcmp(applied[e->seq].body, body) == 0,
			    "%s applied at %ju (%ju %s=%s), another node "
			    "(%ju %s=%s)", n->name, (uintmax_t)e->seq,
			    (uintmax_t)e->term, e->name, body,
			    (uintmax_t)applied[e->seq].term,
			    applied[e->seq].name, applied[e->seq].body);
		if (e->name[0] != '\0' && sscanf(e->name, "doc%d", &doc) == 1 &&
		    doc >= 0 && doc < DOCS_MAX)
			strlcpy(n->d.docs[doc], e->gone ? "" : body,
			    sizeof(n->d.docs[0]));
	}
}

static void
start(int i)
{
	struct node	*n = &nodes[i];
	const char	*peers[NODES_MAX];
	size_t		 k;
	int		 j, np;

	np = 0;
	for (j = 0; j < nn; j++)
		if (j != i)
			peers[np++] = nodes[j].name;
	craft_free(&n->c);
	craft_init(&n->c, n->name, peers, np, now, rnd() | 1);
	craft_restore(&n->c, n->d.term, n->d.vote, n->d.base_term,
	    n->d.base_seq);
	for (k = 0; k < n->d.nlog; k++)
		ATF_REQUIRE(craft_restore_entry(&n->c, n->d.log[k].term,
		    n->d.log[k].seq, n->d.log[k].name, n->d.log[k].body,
		    n->d.log[k].len, n->d.log[k].gone) == 0);
	n->up = true;
}

static void
deliver(void)
{
	struct wire	*w;
	struct node	*n;
	size_t		 i, k;

	for (i = 0; i < MSGS_MAX; i++) {
		w = &wires[i];
		if (!w->used || w->at > now)
			continue;
		n = &nodes[w->to];
		if (n->up) {
			if (w->snap) {
				/* The documents taken whole, then the base;
				 * none older than what it applied. */
				if (w->m.term >= n->c.term) {
					if (craft_snapshot_wanted(&n->c,
					    w->m.term, w->snap_seq))
						memcpy(n->d.docs, w->docs,
						    sizeof(n->d.docs));
					craft_install_snapshot(&n->c, w->m.term,
					    w->snap_term, w->snap_seq,
					    w->m.from);
					after(w->to);
					/* And the leader told. */
					if (node_of(w->m.from) >= 0 &&
					    nodes[node_of(w->m.from)].up) {
						craft_snapshot_done(&nodes[
						    node_of(w->m.from)].c,
						    n->name, w->snap_seq);
						after(node_of(w->m.from));
					}
				}
			} else {
				craft_recv(&n->c, &w->m);
				if (crash_p > 0.0 && (double)(rnd() % 10000) /
				    10000.0 < crash_p)
					n->up = false;	/* before it kept it */
				else
					after(w->to);
			}
		}
		for (k = 0; k < w->m.nentries; k++) {
			free(w->m.entries[k].name);
			free(w->m.entries[k].body);
		}
		free(w->m.entries);
		w->used = false;
	}
}

/* Proposals of the leaders said committed once they are. */
static void
check_props(void)
{
	const struct craft_entry *e;
	struct node		*n;
	int			 p;

	for (p = 0; p < nprops; p++) {
		if (props[p].done)
			continue;
		n = &nodes[props[p].node];
		if (!n->up || n->c.term != props[p].term || n->c.role !=
		    CRAFT_LEADER) {
			props[p].done = true;	/* not said either way */
			continue;
		}
		if (n->c.commit < props[p].seq)
			continue;
		e = craft_entry_at(&n->c, props[p].seq);
		/* Compacted away once applied: committed all the same. */
		if (e == NULL || (e->term == props[p].term && strcmp(e->name,
		    props[p].name) == 0)) {
			ATF_REQUIRE(nacks < ACKS_MAX);
			acks[nacks].term = props[p].term;
			acks[nacks].seq = props[p].seq;
			strlcpy(acks[nacks].name, props[p].name,
			    sizeof(acks[0].name));
			strlcpy(acks[nacks].body, props[p].body,
			    sizeof(acks[0].body));
			nacks++;
		}
		props[p].done = true;
	}
}

/* No two nodes up hold a lease at once. */
static void
leases_one(uint32_t s)
{
	int	i, n, first;

	for (i = 0, n = 0, first = -1; i < nn; i++)
		if (nodes[i].up && craft_quorum_heard(&nodes[i].c,
		    CRAFT_LEASE_MS)) {
			ATF_REQUIRE_MSG(n == 0, "seed %u: %s and %s hold a lease "
			    "at once (terms %ju, %ju), at %ju", s,
			    nodes[first].name, nodes[i].name,
			    (uintmax_t)nodes[first].c.term,
			    (uintmax_t)nodes[i].c.term, (uintmax_t)now);
			first = i;
			n++;
		}
}

static void
run(int nodes_n, uint32_t s, int steps, bool snapshots)
{
	uint64_t	 term, seq;
	char		 body[64], name[32];
	int		 i, j, step, k, leaders, led = 0;

	memset(nodes, 0, sizeof(nodes));
	memset(leader_of_term, 0, sizeof(leader_of_term));
	memset(severed, 0, sizeof(severed));
	nn = nodes_n;
	seed = s;
	now = 1000;
	nacks = nprops = 0;
	drop_p = 0.05;
	if (wires == NULL)
		wires = calloc(MSGS_MAX, sizeof(*wires));
	if (applied == NULL)
		applied = calloc(SEQS_MAX, sizeof(*applied));
	memset(wires, 0, MSGS_MAX * sizeof(*wires));
	memset(applied, 0, SEQS_MAX * sizeof(*applied));
	for (i = 0; i < nn; i++) {
		snprintf(nodes[i].name, sizeof(nodes[i].name), "n%d", i);
		part[i] = 0;
	}
	/* The seed: its documents (none) are the base the others are sent;
	 * it alone may lead first. */
	nodes[0].d.term = 1;
	nodes[0].d.base_term = 1;
	nodes[0].d.base_seq = 1;
	for (i = 0; i < nn; i++)
		start(i);
	for (step = 0; step < steps; step++) {
		now += 10;
		/* Now and then: a node crashes, or comes back; the network
		 * is cut, or made whole. */
		k = rnd() % 1000;
		if (k < 3) {
			i = rnd() % nn;
			if (nodes[i].up)
				nodes[i].up = false;
			else
				start(i);
		} else if (k < 5) {
			for (i = 0; i < nn; i++)
				part[i] = rnd() % 2;
		} else if (k < 8) {
			for (i = 0; i < nn; i++)
				part[i] = 0;
		}
		for (i = 0; i < nn; i++)
			if (nodes[i].up) {
				craft_tick(&nodes[i].c, now);
				after(i);
			}
		deliver();
		for (i = 0; i < nn; i++)
			if (nodes[i].up && nodes[i].c.role == CRAFT_LEADER) {
				led++;
				break;
			}
		leases_one(s);
		/* A write, to whoever leads, one step in three. */
		k = rnd() % 3;
		for (i = 0; k == 0 && i < nn; i++)
			if (nodes[i].up && nodes[i].c.role == CRAFT_LEADER &&
			    nprops < ACKS_MAX) {
				snprintf(name, sizeof(name), "doc%u", rnd() %
				    DOCS_MAX);
				snprintf(body, sizeof(body), "v%d.%u", step,
				    rnd() % 1000);
				if (craft_propose(&nodes[i].c, name,
				    (const uint8_t *)body, strlen(body), false,
				    &term, &seq) == 0) {
					props[nprops].node = i;
					props[nprops].term = term;
					props[nprops].seq = seq;
					strlcpy(props[nprops].name, name,
					    sizeof(props[0].name));
					strlcpy(props[nprops].body, body,
					    sizeof(props[0].body));
					props[nprops].done = false;
					nprops++;
				}
				after(i);
			}
		if (snapshots && step % 50 == 0)
			for (i = 0; i < nn; i++)
				if (nodes[i].up) {
					craft_compact(&nodes[i].c, 5);
					after(i);
				}
		check_props();
	}
	/* Whole again, nobody lost, nothing dropped: it settles. */
	drop_p = 0.0;
	crash_p = 0.0;
	for (i = 0; i < nn; i++) {
		part[i] = 0;
		if (!nodes[i].up)
			start(i);
	}
	for (step = 0; step < 3000; step++) {
		now += 10;
		for (i = 0; i < nn; i++) {
			craft_tick(&nodes[i].c, now);
			after(i);
		}
		deliver();
		check_props();
	}
	leaders = 0;
	for (i = 0; i < nn; i++)
		if (nodes[i].c.role == CRAFT_LEADER)
			leaders++;
	ATF_REQUIRE_MSG(leaders == 1, "seed %u: %d leaders in the end", s,
	    leaders);
	for (i = 1; i < nn; i++)
		ATF_REQUIRE_MSG(nodes[i].c.applied == nodes[0].c.applied,
		    "seed %u: %s applied %ju, %s %ju", s, nodes[i].name,
		    (uintmax_t)nodes[i].c.applied, nodes[0].name,
		    (uintmax_t)nodes[0].c.applied);
	for (i = 1; i < nn; i++)
		for (j = 0; j < DOCS_MAX; j++)
			ATF_REQUIRE_MSG(strcmp(nodes[i].d.docs[j],
			    nodes[0].d.docs[j]) == 0, "seed %u: doc%d %s on %s, "
			    "%s on %s", s, j, nodes[i].d.docs[j], nodes[i].name,
			    nodes[0].d.docs[j], nodes[0].name);
	/* Every write said committed is where it was said to be. */
	for (k = 0; k < nacks; k++)
		ATF_REQUIRE_MSG(applied[acks[k].seq].set && applied[
		    acks[k].seq].term == acks[k].term && strcmp(applied[
		    acks[k].seq].body, acks[k].body) == 0, "seed %u: the "
		    "write %s=%s said committed at %ju was not applied there",
		    s, acks[k].name, acks[k].body, (uintmax_t)acks[k].seq);
	if (getenv("RAFT_DEBUG") != NULL)
		fprintf(stderr, "seed %u: %d nodes, %d proposals, %d committed, "
		    "%d steps led, terms to %ju\n", s, nn, nprops, nacks, led,
		    (uintmax_t)nodes[0].c.term);
	/* Live once whole: twenty writes to the leader, each committed and
	 * applied everywhere. */
	for (i = 0; i < nn && nodes[i].c.role != CRAFT_LEADER; i++)
		;
	k = nacks;
	for (j = 0; j < 20; j++) {
		snprintf(name, sizeof(name), "doc%d", j % DOCS_MAX);
		snprintf(body, sizeof(body), "final%d", j);
		ATF_REQUIRE(craft_propose(&nodes[i].c, name, (const uint8_t *)
		    body, strlen(body), false, &term, &seq) == 0);
		props[nprops].node = i;
		props[nprops].term = term;
		props[nprops].seq = seq;
		strlcpy(props[nprops].name, name, sizeof(props[0].name));
		strlcpy(props[nprops].body, body, sizeof(props[0].body));
		props[nprops].done = false;
		nprops++;
		after(i);
	}
	for (step = 0; step < 300; step++) {
		now += 10;
		for (j = 0; j < nn; j++) {
			craft_tick(&nodes[j].c, now);
			after(j);
		}
		deliver();
		check_props();
	}
	ATF_REQUIRE_MSG(nacks - k == 20, "seed %u: %d of the 20 last writes "
	    "committed", s, nacks - k);
	for (j = 0; j < nn; j++)
		ATF_REQUIRE_MSG(strcmp(nodes[j].d.docs[19 % DOCS_MAX], "final19")
		    == 0 && nodes[j].c.applied == nodes[i].c.applied, "seed %u: "
		    "%s has not applied the last writes", s, nodes[j].name);
	for (k = 0; k < nacks; k++)
		ATF_REQUIRE_MSG(applied[acks[k].seq].set && applied[
		    acks[k].seq].term == acks[k].term && strcmp(applied[
		    acks[k].seq].body, acks[k].body) == 0, "seed %u: the "
		    "write %s=%s said committed at %ju was not applied there",
		    s, acks[k].name, acks[k].body, (uintmax_t)acks[k].seq);
	for (i = 0; i < nn; i++) {
		craft_free(&nodes[i].c);
		entries_free(nodes[i].d.log, nodes[i].d.nlog);
	}
}

ATF_TC_WITHOUT_HEAD(one);
ATF_TC_BODY(one, tc)
{
	struct craft	 c;
	const struct craft_entry *e;
	uint64_t	 term, seq;

	/* Alone, it leads at its first deadline and commits at once; but
	 * not while it holds nothing, and is not the seed. */
	craft_init(&c, "solo", NULL, 0, 0, 7);
	craft_tick(&c, 10000);
	ATF_REQUIRE_EQ(CRAFT_FOLLOWER, c.role);
	craft_restore(&c, 1, "", 1, 1);
	craft_tick(&c, 20000);
	ATF_REQUIRE_EQ(CRAFT_LEADER, c.role);
	ATF_REQUIRE(craft_propose(&c, "a", (const uint8_t *)"x", 1, false,
	    &term, &seq) == 0);
	ATF_REQUIRE_EQ(seq, c.commit);
	/* The leader's empty write first, then this one. */
	e = craft_next_apply(&c);
	ATF_REQUIRE(e != NULL && e->name[0] == '\0');
	e = craft_next_apply(&c);
	ATF_REQUIRE(e != NULL && strcmp(e->name, "a") == 0);
	ATF_REQUIRE(craft_next_apply(&c) == NULL);
	craft_free(&c);
}

ATF_TC_WITHOUT_HEAD(three);
ATF_TC_BODY(three, tc)
{
	uint32_t	s;

	for (s = 1; s <= 40; s++)
		run(3, s * 2654435761u, 3000, false);
}

ATF_TC_WITHOUT_HEAD(five);
ATF_TC_BODY(five, tc)
{
	uint32_t	s;

	for (s = 1; s <= 25; s++)
		run(5, s * 40503u + 17, 3000, false);
}

/*
 * A leader cut off from the majority steps down within an election's
 * time, and grants nothing on its lease before that; the three elect
 * another, and at no moment do two hold a lease at once.
 */
ATF_TC_WITHOUT_HEAD(partition);
ATF_TC_BODY(partition, tc)
{
	uint64_t	 cut, down_at;
	int		 i, step, old, new, leases;

	memset(nodes, 0, sizeof(nodes));
	memset(leader_of_term, 0, sizeof(leader_of_term));
	nn = 5;
	seed = 7;
	now = 1000;
	nacks = nprops = 0;
	drop_p = 0.0;
	if (wires == NULL)
		wires = calloc(MSGS_MAX, sizeof(*wires));
	if (applied == NULL)
		applied = calloc(SEQS_MAX, sizeof(*applied));
	memset(wires, 0, MSGS_MAX * sizeof(*wires));
	memset(applied, 0, SEQS_MAX * sizeof(*applied));
	for (i = 0; i < nn; i++) {
		snprintf(nodes[i].name, sizeof(nodes[i].name), "n%d", i);
		part[i] = 0;
	}
	nodes[0].d.term = 1;
	nodes[0].d.base_term = 1;
	nodes[0].d.base_seq = 1;
	for (i = 0; i < nn; i++)
		start(i);
	for (old = -1, step = 0; step < 1000 && old < 0; step++) {
		now += 10;
		for (i = 0; i < nn; i++) {
			craft_tick(&nodes[i].c, now);
			after(i);
		}
		deliver();
		/* A leader with a lease, and every node holding the log (one
		 * that holds nothing yet never elects). */
		for (i = 0; i < nn; i++)
			if (nodes[i].c.role == CRAFT_LEADER &&
			    craft_quorum_heard(&nodes[i].c, CRAFT_LEASE_MS))
				old = i;
		for (i = 0; old >= 0 && i < nn; i++)
			if (craft_last_seq(&nodes[i].c) == 0)
				old = -1;
	}
	ATF_REQUIRE_MSG(old >= 0, "no leader with a lease, or a node with "
	    "nothing");
	/* The leader and one other on one side, three on the other. */
	part[old] = 1;
	part[(old + 1) % nn] = 1;
	cut = now;
	down_at = 0;
	new = -1;
	for (step = 0; step < 1000; step++) {
		now += 10;
		for (i = 0; i < nn; i++) {
			craft_tick(&nodes[i].c, now);
			after(i);
		}
		deliver();
		/* Its lease is over within the lease's time, itself within
		 * an election's; then it is a leader no more. */
		if (now - cut > CRAFT_LEASE_MS + 50)
			ATF_REQUIRE_MSG(!craft_quorum_heard(&nodes[old].c,
			    CRAFT_LEASE_MS), "the cut-off leader keeps its lease "
			    "%ju ms on", (uintmax_t)(now - cut));
		if (down_at == 0 && nodes[old].c.role != CRAFT_LEADER)
			down_at = now;
		leases = 0;
		for (i = 0; i < nn; i++)
			if (craft_quorum_heard(&nodes[i].c, CRAFT_LEASE_MS)) {
				leases++;
				if (i != old)
					new = i;
			}
		ATF_REQUIRE_MSG(leases <= 1, "two leaders hold a lease at once");
	}
	ATF_REQUIRE_MSG(down_at != 0 && down_at - cut <= CRAFT_ELECTION_MIN_MS +
	    CRAFT_HEARTBEAT_MS + 50, "the cut-off leader stepped down after "
	    "%ju ms", (uintmax_t)(down_at - cut));
	ATF_REQUIRE_MSG(new >= 0 && part[new] == 0, "the majority elected no "
	    "leader with a lease");
	for (i = 0; i < nn; i++) {
		craft_free(&nodes[i].c);
		entries_free(nodes[i].d.log, nodes[i].d.nlog);
	}
}

static int	step_all(void);

/* n nodes on a whole network that drops nothing: the leader once it holds
 * a lease and every node holds the log. */
static int
boot(int n, uint32_t s)
{
	int	i, step, lead;

	memset(nodes, 0, sizeof(nodes));
	memset(leader_of_term, 0, sizeof(leader_of_term));
	memset(severed, 0, sizeof(severed));
	nn = n;
	seed = s;
	now = 1000;
	nacks = nprops = 0;
	drop_p = crash_p = 0.0;
	if (wires == NULL)
		wires = calloc(MSGS_MAX, sizeof(*wires));
	if (applied == NULL)
		applied = calloc(SEQS_MAX, sizeof(*applied));
	memset(wires, 0, MSGS_MAX * sizeof(*wires));
	memset(applied, 0, SEQS_MAX * sizeof(*applied));
	for (i = 0; i < nn; i++) {
		snprintf(nodes[i].name, sizeof(nodes[i].name), "n%d", i);
		part[i] = 0;
	}
	nodes[0].d.term = 1;
	nodes[0].d.base_term = 1;
	nodes[0].d.base_seq = 1;
	for (i = 0; i < nn; i++)
		start(i);
	for (lead = -1, step = 0; step < 1000 && lead < 0; step++)
		lead = step_all();
	ATF_REQUIRE_MSG(lead >= 0, "no leader with a lease, or a node with "
	    "nothing");
	return (lead);
}

/* A step of every node, the network's messages delivered: the leader
 * with a lease, once every node holds the log, or -1. */
static int
step_all(void)
{
	int	i, lead;

	now += 10;
	for (i = 0; i < nn; i++)
		if (nodes[i].up) {
			craft_tick(&nodes[i].c, now);
			after(i);
		}
	deliver();
	leases_one(seed);
	for (lead = -1, i = 0; i < nn; i++)
		if (nodes[i].up && nodes[i].c.role == CRAFT_LEADER &&
		    craft_quorum_heard(&nodes[i].c, CRAFT_LEASE_MS))
			lead = i;
	for (i = 0; lead >= 0 && i < nn; i++)
		if (craft_last_seq(&nodes[i].c) == 0)
			lead = -1;
	return (lead);
}

static void
unboot(void)
{
	int	i;

	for (i = 0; i < nn; i++) {
		craft_free(&nodes[i].c);
		entries_free(nodes[i].d.log, nodes[i].d.nlog);
	}
}

/*
 * Three nodes, the link between the leader and one other cut, the rest
 * whole: that one hears no leader and asks to be elected, the third, who
 * hears the leader, refuses it.  At no moment do two hold a lease, and
 * the leader keeps its place and its term.
 */
ATF_TC_WITHOUT_HEAD(two_leaders);
ATF_TC_BODY(two_leaders, tc)
{
	uint64_t	term;
	int		lead, other, step;

	lead = boot(3, 11);
	other = (lead + 1) % 3;
	term = nodes[lead].c.term;
	severed[lead][other] = severed[other][lead] = true;
	for (step = 0; step < 1000; step++)
		(void)step_all();
	ATF_CHECK_MSG(nodes[lead].c.role == CRAFT_LEADER &&
	    nodes[lead].c.term == term, "the leader lost its place: %s, term "
	    "%ju of %ju", nodes[lead].c.role == CRAFT_LEADER ? "leads" :
	    "does not lead", (uintmax_t)nodes[lead].c.term, (uintmax_t)term);
	ATF_CHECK_MSG(nodes[other].c.term == term, "the cut-off node raised "
	    "its term to %ju from %ju", (uintmax_t)nodes[other].c.term,
	    (uintmax_t)term);
	unboot();
}

/*
 * A node cut off from every other for ten seconds asks to be elected
 * again and again with its term as it was (the pre-vote), and back on
 * the network unseats nobody.
 */
ATF_TC_WITHOUT_HEAD(prevote);
ATF_TC_BODY(prevote, tc)
{
	uint64_t	term;
	int		lead, other, step;

	lead = boot(3, 13);
	other = (lead + 2) % 3;
	term = nodes[lead].c.term;
	part[other] = 1;
	for (step = 0; step < 1000; step++)
		(void)step_all();
	ATF_CHECK_MSG(nodes[other].c.term == term, "cut off, its term went "
	    "from %ju to %ju", (uintmax_t)term, (uintmax_t)nodes[other].c.term);
	part[other] = 0;
	for (step = 0; step < 500; step++)
		(void)step_all();
	ATF_CHECK_MSG(nodes[lead].c.role == CRAFT_LEADER &&
	    nodes[lead].c.term == term, "back, it unseated the leader: term "
	    "%ju of %ju", (uintmax_t)nodes[lead].c.term, (uintmax_t)term);
	unboot();
}

/*
 * A follower that heard from the leader within the least election time
 * refuses another's vote, and keeps its term; past it, it gives it.
 */
ATF_TC_WITHOUT_HEAD(vote_refused);
ATF_TC_BODY(vote_refused, tc)
{
	struct craft		 c;
	struct craft_msg	 m;
	const char		*peers[] = { "a", "c" };

	craft_init(&c, "b", peers, 2, 1000, 5);
	craft_restore(&c, 1, "", 1, 1);
	memset(&m, 0, sizeof(m));
	m.type = CRAFT_APPEND;
	strlcpy(m.from, "a", sizeof(m.from));
	strlcpy(m.to, "b", sizeof(m.to));
	m.term = 2;
	m.prev_term = 1;
	m.prev_seq = 1;
	m.commit = 1;
	craft_recv(&c, &m);
	ATF_REQUIRE_EQ(2, c.term);
	craft_out_clear(&c);
	craft_tick(&c, 1100);
	craft_out_clear(&c);
	memset(&m, 0, sizeof(m));
	m.type = CRAFT_VOTE;
	strlcpy(m.from, "c", sizeof(m.from));
	strlcpy(m.to, "b", sizeof(m.to));
	m.term = 3;
	m.last_term = 1;
	m.last_seq = 1;
	craft_recv(&c, &m);
	ATF_REQUIRE_EQ(1, (int)c.nout);
	ATF_CHECK_MSG(c.out[0].type == CRAFT_VOTE_REPLY && !c.out[0].granted,
	    "a vote given 100 ms after the leader was heard");
	ATF_CHECK_EQ_MSG(2, c.term, "its term taken from the vote: %ju",
	    (uintmax_t)c.term);
	craft_out_clear(&c);
	/* An election's least time later, the leader silent: given. */
	craft_tick(&c, 1000 + CRAFT_ELECTION_MIN_MS + 10);
	craft_out_clear(&c);
	craft_recv(&c, &m);
	ATF_REQUIRE(c.nout >= 1);
	ATF_CHECK_MSG(c.out[c.nout - 1].type == CRAFT_VOTE_REPLY &&
	    c.out[c.nout - 1].granted && c.term == 3, "the vote refused once "
	    "the leader was silent");
	craft_free(&c);
}

/* Elections throughout, and the network cut and whole again: no lease at
 * a leader's election, no two at once (after() and leases_one()). */
ATF_TC_WITHOUT_HEAD(lease_from_acks);
ATF_TC_BODY(lease_from_acks, tc)
{
	uint32_t	s;

	for (s = 1; s <= 10; s++)
		run(3, s * 7919u + 1, 2000, false);
	for (s = 1; s <= 5; s++)
		run(5, s * 104729u + 3, 2000, false);
}

/*
 * The documents installed at a write this follower holds of the same
 * term keep the writes after it; documents older than what it applied
 * are not taken.
 */
ATF_TC_WITHOUT_HEAD(snapshot_suffix);
ATF_TC_BODY(snapshot_suffix, tc)
{
	struct craft		 c;
	const struct craft_entry *e;
	const char		*peers[] = { "a", "c" };
	char			 name[8];
	uint64_t		 seq;

	craft_init(&c, "b", peers, 2, 1000, 5);
	craft_restore(&c, 2, "", 1, 1);
	for (seq = 2; seq <= 6; seq++) {
		snprintf(name, sizeof(name), "d%ju", (uintmax_t)seq);
		ATF_REQUIRE(craft_restore_entry(&c, 2, seq, name,
		    (const uint8_t *)"x", 1, false) == 0);
	}
	craft_install_snapshot(&c, 2, 2, 4, "a");
	ATF_CHECK_EQ(4, c.base_seq);
	ATF_CHECK_EQ(6, craft_last_seq(&c));
	e = craft_entry_at(&c, 5);
	ATF_CHECK_MSG(e != NULL && strcmp(e->name, "d5") == 0, "the writes "
	    "after the documents, which agree, taken away");
	/* Back to 3: not taken, nothing changed. */
	craft_install_snapshot(&c, 2, 2, 3, "a");
	ATF_CHECK_EQ_MSG(4, c.base_seq, "the documents went back to %ju",
	    (uintmax_t)c.base_seq);
	ATF_CHECK_EQ(4, c.applied);
	ATF_CHECK(craft_entry_at(&c, 6) != NULL);
	/* Of another term at 6: none of its writes kept. */
	craft_install_snapshot(&c, 2, 3, 6, "a");
	ATF_CHECK_EQ(6, c.base_seq);
	ATF_CHECK_EQ(0, c.nlog);
	craft_free(&c);
}

/*
 * A lock is a write of the log: proposed by a leader cut off at once, and
 * written over by the one the others elect, it was never applied as it
 * was proposed, which is what its holder waits to see.
 */
ATF_TC_WITHOUT_HEAD(lock_overwritten);
ATF_TC_BODY(lock_overwritten, tc)
{
	uint64_t	term, seq, t2, s2;
	int		lead, i, step, other;

	lead = boot(3, 17);
	part[lead] = 1;
	ATF_REQUIRE(craft_propose(&nodes[lead].c, "\001lock\001x",
	    (const uint8_t *)"h\n30000", 7, false, &term, &seq) == 0);
	after(lead);
	for (other = -1, step = 0; step < 1000 && other < 0; step++) {
		(void)step_all();
		for (i = 0; i < nn; i++)
			if (i != lead && nodes[i].c.role == CRAFT_LEADER &&
			    craft_quorum_heard(&nodes[i].c, CRAFT_LEASE_MS))
				other = i;
	}
	ATF_REQUIRE_MSG(other >= 0, "the other two elected none");
	ATF_REQUIRE(craft_propose(&nodes[other].c, "doc1", (const uint8_t *)
	    "v", 1, false, &t2, &s2) == 0);
	after(other);
	part[lead] = 0;
	for (step = 0; step < 500; step++)
		(void)step_all();
	ATF_REQUIRE_MSG(nodes[lead].c.applied >= seq, "the old leader has "
	    "not caught up: %ju of %ju", (uintmax_t)nodes[lead].c.applied,
	    (uintmax_t)seq);
	ATF_CHECK_MSG(!craft_applied_as(&nodes[lead].c, seq, term), "the "
	    "lock written over was applied as it was proposed");
	ATF_CHECK(craft_applied_as(&nodes[lead].c, seq,
	    nodes[other].c.term));
	unboot();
}

/* Nodes that stop between a message and keeping what it changed: safe
 * all the same (nothing was said that was not kept). */
ATF_TC_WITHOUT_HEAD(crash_before_keep);
ATF_TC_BODY(crash_before_keep, tc)
{
	uint32_t	s;

	for (s = 1; s <= 15; s++) {
		crash_p = 0.002;
		run(3, s * 6151u + 7, 3000, s % 2 == 0);
	}
	for (s = 1; s <= 8; s++) {
		crash_p = 0.002;
		run(5, s * 12289u + 9, 3000, s % 2 == 0);
	}
}

ATF_TC_WITHOUT_HEAD(snapshots);
ATF_TC_BODY(snapshots, tc)
{
	uint32_t	s;

	for (s = 1; s <= 30; s++)
		run(3, s * 97u + 3, 3000, true);
	for (s = 1; s <= 15; s++)
		run(5, s * 131u + 5, 3000, true);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, one);
	ATF_TP_ADD_TC(tp, three);
	ATF_TP_ADD_TC(tp, five);
	ATF_TP_ADD_TC(tp, snapshots);
	ATF_TP_ADD_TC(tp, partition);
	ATF_TP_ADD_TC(tp, two_leaders);
	ATF_TP_ADD_TC(tp, prevote);
	ATF_TP_ADD_TC(tp, vote_refused);
	ATF_TP_ADD_TC(tp, lease_from_acks);
	ATF_TP_ADD_TC(tp, snapshot_suffix);
	ATF_TP_ADD_TC(tp, lock_overwritten);
	ATF_TP_ADD_TC(tp, crash_before_keep);
	return (atf_no_error());
}
