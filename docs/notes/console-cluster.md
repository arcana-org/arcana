# Console clustering, active/active

The console runs as a cluster of nodes, active/active, by Raft over
cblink between the consoles: no database and no shared file system.
It is built only when chosen: `WITH_CLUSTER=yes` (config.mk, `make
config`) or the port's `CLUSTER` option, off by default; without it
`nocluster.c` stands in, a `cluster` block in web.conf stops the
console, and `make check` compiles the console the other way too.
Every store is a whole JSON document (`store_save()` writes the file
whole), so the stores replicate as documents, without a log of
operations.

## What active/active needs

1. Every store readable and writable from every node, with a change
   on one seen by the others before the next request lands anywhere
   (an admin's two clicks may go to two nodes).
2. The schedulers and the manager loop running once in the cluster at
   a time, with another node taking over when the holder dies.
3. Sessions valid on every node: a cookie set by one accepted by all.
4. The audit chain appended in one order.
5. Each node reaching every agent (they are IPv6/TCP with client
   certificates; nothing to change), and the hosts' events followed by
   whichever node a browser is on.  The agents trust the console by its
   certificate (`urn:arcana:role:console`), so every node with the
   same CA and a console certificate is a console to them.

## How it works

- **Membership.** Each node is named in `cluster { node … }` of web.conf
  with its cblink URI and its origin; three nodes at least. Nodes talk
  over a family of their own, `arcana-cluster` (its own IDL,
  `share/arcana/cluster.yaml`), on a listener of each console's, with
  mutual TLS by certificates of the console's CA that say
  `URI:urn:arcana:role:console` and serve as well as dial.
- **Raft.** `craft.c` is Raft as a state machine without I/O, tested
  by simulation (`tests/raft_test.c`: three and five nodes through
  drops, delays, duplicates, partitions, crashes and compaction, a link
  cut alone).  A node votes once a term, only for a candidate whose
  log is as new as its own, and for none while it heard from a leader
  within the least election time (the thesis' 4.2.3); a node asks for
  pre-votes before it raises its term (9.6), so one cut off comes back
  unseating nobody.  A majority makes a leader, whose lease is
  reckoned from when what a majority answered in its term was sent,
  less a drift bound, never whole at its election; a leader no
  majority answers within an election's time steps down.  A node with
  an empty log never stands: the seed (the first node named) leads
  first, from the documents it has.
- **Writes.** `nodes.c` is the I/O: the term, the vote and the log in
  `<datadir>/cluster`, written and fsync'ed (the directory too, for a
  rename) by a writer thread, batch after batch, the messages and the
  replies each turn of craft made sent only once its batch is kept; a
  thread a peer.  `store_save()` is `cluster_save()`: the leader numbers the
  document, sends it to every follower and answers once a majority
  holds it and it is written; a follower forwards its write to the
  leader and waits for the same.  Committed writes are applied with
  `store_write()` on every node alike; a node too far behind is sent
  the documents whole, which never take it back past what it applied,
  and it keeps the writes after them it holds.  A follower's write the
  leader committed and the follower has not written within the wait
  is accepted: the node's replies carry `Warning: 110` and its
  `cluster` says `behind` until it has.
- **Reads** are each node's own files: active/active.
- **Locks.** The read-change-write stores (labels, templates, prefix
  lists) take the cluster's lock besides their flock(2), and an SD-WAN
  apply takes `sdwan.apply`.  A lock is a write of the log (its holder
  and how long), applied by every node to its table by its own clock,
  so a new leader knows the locks of the one before; a leader grants
  on its lease, once its first write of its term is committed.  It is
  held once its own write is applied here as it was given (which
  writes every write committed before it); its fencing token is that
  write's sequence, kept while the holder renews it.  The apply checks
  its lock and token (renewing it) before each step's jobs, and stops
  when it is lost.
- **Caches.** What the worker keeps in memory (credentials, sessions,
  users, servers, push subscriptions) is read again when another
  node's write of its store lands.
- **What runs once.** The workflow scheduler, the SD-WAN manager loop
  and the mail watcher run on the leader alone, while it holds its
  lease and once its first write of its term is committed.
- **Sessions** are a document each (`sessions/<hash>.json`): a
  sign-in, an end, a time of use each its own write, so sign-ins on
  two nodes at once are both kept and an end is not undone by another
  node.
- **The browser.** Each node keeps its own origin; the WebAuthn RP ID
  is a name the nodes share (`console.example` for
  `a.console.example`, `b.console.example`), and the WebAuthn, CSRF
  and stream checks take every node's origin.
- **Without a majority** a node still reads, and refuses changes,
  saying the cluster has no majority here.
- Settings › Cluster and `GET arcana-console:cluster` show it; console_test:cluster
  runs three consoles over unix sockets.

- **Tokens.** The setup token and the enrolment tokens are the log's,
  not a node's memory (`nodes.c`, the tokens' section): each change a
  write named `\001token\001` and its kind, its body lines of
  `key=value`, an empty line, and (a setup alone) a document.  The
  kinds: `setup-token` (`hash`, `node`, `time`), the leader's new setup
  token; `setup` (`hash`, `doc`, `time`, then `credentials.json` or
  `users.json` whole), the first owner; `enrol-token` (`hash`, `name`,
  `host`, `port`, `ttl`, `time`); `enrol` (`hash`, `time`), a spend.
  `hash` is the SHA-256 of the token's secret, never the secret; the
  leader proposes every one, a follower's sent to it, and puts its own
  clock's `time` in it (what the follower said is not taken).  Every
  node applies them alike, in order, to its table and to
  `cluster-tokens.json` (which the documents sent to a node carry, with
  the last token write applied, so a restart applies none twice); a
  write that does not read (sizes, keys, a kind, a document that is not
  one of the two) changes nothing.  A spend holds when its token is
  there, unspent, compared in constant time: of two committed the first
  wins on every node, and what came of it is read where it was asked
  once it is applied there.  An enrolment token lasts `enrol_ttl` from
  the `time` of the write that made it, and is judged against the
  `time` of each later token write, the leader's clock alone deciding.
  A node knows a token once it has applied the write that made it (a
  heartbeat after the leader); asked before, it knows none, and no write
  of the log is made for a token the node does not know.
  The setup token is made by the node that leads, on its lease and once
  its first write of its term is committed: its text in that node's
  `setup-token`, the others' files taken away; a new leader makes
  another.  A node with no leader says so instead of making one.  The
  first owner (a key's `credentials.json`, or a password's `users.json`)
  is written only by the `setup` write that spends the token; after
  one, no `setup-token` is taken.
- **Per node.** The audit trail (`sdwan-audit.jsonl`, under each node's
  own key) and the SENs and SANs (`sdwan-sen.jsonl`, `sdwan-san.jsonl`)
  are each node's own: each record names its `node`.

## Not yet

- Files written besides `store_save()`: `vapid.pem` (push), the audit
  chain and the notices (per node, above: one trail wants appends
  through the log, an entry kind idempotent by a record id),
  `arcana-source.json`, the CA's next state.
- Membership changes: the nodes are web.conf's; adding one is a restart
  of each with the new block.
- A cluster of two nodes and a witness.
