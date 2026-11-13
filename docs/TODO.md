# TODO

## To do

- IPFIX export in ng_netflow(4), kernel work and the user's:
  ng_netflow exports NetFlow v5 and v9 only (both hooks at once,
  nothing else); pflow(4) has IPFIX but serves pf.
  docs/PLAN-SDN-YANG.md's flow telemetry (5.6) waits on it or takes v9.
  An expired flow also waits in a partly filled export datagram until
  it fills or the node shuts down, with no timer to send it; a flush
  belongs to the same work.
- The SDN and YANG redesign: docs/PLAN-SDN-YANG.md. Open decisions:
  D-5, D-11, D-12 (D-6 taken: a FIB per vpn-node).
  To do, the datastores first, to the safety design decided on
  2026-10-28 (in the plan, 2.3): 2.3.x (candidate and
  running), 2.3.5 the rc.conf.d
  fragments rendered (the agent edits rc.conf through sysrc(8)), the
  running datastore's use of rtadvd.conf (2.5.1); RESTCONF (Y-4).
  The interim family is gone (3.8, 0.238.0/0.336.0): every operation
  is a YANG module's, its task's { } Schema panel showing the
  module's tree.
  For the user: the CORECONF draft's examples number some
  ietf-interfaces items otherwise than SIDS.md.
- MEF 138's model, what stays undone and why (docs/PLAN-119-SASE.md,
  SASE-6): the middlebox for IPsec (no IPsec proxy on FreeBSD) and
  DLP (no engine). The book's conformance rows are to be brought up to
  SASE-6: SEN and SAN, MD+R hashes, DNF's inner wildcards, PDNS's
  CNAME and NS entries and DNS over TLS, DPF's message types.
- Each a task of its own, in no order yet:
  - Disaster recovery across console clusters.
  - Agents in an HA pair on identical hardware and ports, the pair's
    state shared; ipfw has no pfsync, which is pf's: how the state is
    shared is the user's to decide.
- A geneve tunnel's forwarding table: if_geneve keeps one and shows
  no way to read it from userland (no sysctl as vxlan has, no dump
  through netlink); once it does, shown as a bridge's addresses are.
- The alerts' cases (Settings, Notifications; mail-case and
  telegram-case) are named in the page (actions.c, known_cases) after
  the agent's fault types (gula/yalarms.c, kinds[]), by hand: a type a
  newer agent raises is told on every way, as the default says, and has
  a row once a way keeps an entry for it, but none before it is named
  there.  The console's own settings have no { } Schema panel: no
  operation of share/arcana/yang-ops is arcana-console's.
- The mesh: agents joined by SCTP associations, each to at least a
  configured number of others (2 unless set), so that the console
  reaches an agent it has lost through one it still has. SCTP only,
  with no fallback to TCP: a blocked or failed association is a state
  to show and to route around. No module is loaded for it and no
  interface made; an agent on a host without `sctp` in its kernel does
  not try until the console tells it to try again. Who the agents are
  and how they are joined is agreed among them with DNCP (RFC 7787),
  from `libdncp`, a repository of its own.
  To be done, in this order:
  - Certificates with a role: joining the events group, which cblink
    admits below the handlers, is not covered; to be closed in cblink
    with the mesh.
  - Arcana's DNCP profile: over cblink on SCTP with DTLS, its own TLVs
    (an agent's name and mesh addresses, when it last heard the
    console), SCTP's heartbeats instead of keep-alives.
  - The mesh listener, the switch and "try again" for each host in the
    console, and the associations drawn on the map and listed, with
    their state, their paths, their round-trip time and their streams.
  - Relaying, and the console falling back to it; the path named by
    the console from the topology the agents hold.
  Not decided:
  - How an agent picks its neighbours, which DNCP leaves open. The
    proposal: the next ones on a ring ordered by node identifier,
    until enough associations work.
  - Whether a node's data carries its signature. DNCP secures each
    hop, not the data: an agent could publish for another until that
    one publishes again.
  - How a relayed session is carried: end to end, the console's own
    TLS session with the agent inside a stream through the relay,
    which only copies bytes; or hop by hop, the relay reading and
    sending on. End to end needs a cblink connection that runs over a
    cblink stream, which cblink has not got, or a bridge through a
    local socket at both ends.
- The console's store_write() got EBADF once, on the descriptor
  mkstemp(3) had just given it (console 0.275.0, on Kore): another
  thread closed a number it did not own.  Looked for again on
  2026-10-28 and not found in the console as it is now:
  - every console_test case under `ktrace -i -t c`: no system call of
    arcana-console or arcana-agent failed with EBADF;
  - every case again, and console_test:churn twenty times, with a
    preload in the console that reports a close(2) or libc's _close()
    of a descriptor mkstemp(3) gave another thread, any close that
    fails with EBADF, and libwebsockets called off the thread of
    lws_service(): none;
  - read: cblink closes a connection's descriptor in cbl_conn_fail()
    alone, once (its state under the lock), on the loop's thread for a
    connection on a loop; its TLS and DTLS BIOs are BIO_NOCLOSE.
    libwebsockets is built LWS_MAX_SMP 1 and the console calls it
    from the service thread only, lws_cancel_service() aside.
  The likeliest cause was Kore's: kore_log() from threads that were
  not the worker queued on the worker's message connection with no
  lock (the 2026-10-22 review), gone with Kore on 2026-10-25.  Seen
  again, store_write() now says which step failed and on which
  number, and does not close a descriptor EBADF says is no longer
  its own; start from that line, ktrace and the preload.
- arcana-sdwan's instances (the grouping instance, ysd.c) still have
  their configuration as text (conf), as the console wrote it before;
  BIRD's, dnsmasq's, unbound's and Squid's are forms now (spec), which
  the agent renders (luxuria/sdconf.c), as Suricata's already were.
  The module to say the form, or the text the agent rendered.
- A plain tunnel's STAMP key when the FAR end's pair is made again
  (agent 0.277.0): each end derives its key from its own pair and the
  far end's public half, which the console puts in the target
  (`stamp_peer`, `${stamp:SID:IF}` read from the far end's sdwan read
  when the apply runs).  A pair made again at this end is used at the
  next STAMP try without the console (the key derived anew when it
  brings no authenticated answer), but the far end has this end's new
  half only after an apply to it, and this end has the far end's new
  half only after an apply to this end: until then the tunnel's STAMP
  fails authentication, the target is pinged and arcana-alarms'
  stamp-unauthenticated is raised.  Whether the console applies both
  ends when it remakes a pair (or a pair's change is told to it and
  answered by an apply) is open.
- The agent's allocations (work.c's wcalloc, wmalloc and the rest, and
  err(1) on a failed pipe2(2) or realloc(3) in ira/exec.c) end the
  root daemon when memory runs out, a change half done with it; a
  failure of one request's alone, said, is to come.
- The cores' backtraces (gula/crashes.c): root runs lldb(1) and gdb(1)
  on any `*.core` found in /, /root, /tmp, /var/tmp, the BIRD
  directories and each /home/*, a file any local user can plant there.
  To come: only a core the kernel wrote for a real crash (kern.corefile's
  pattern, and a kmsg "exited on signal ... (core dumped)" record of
  that pid and name), owned by the crashed process's uid, a regular
  file, opened O_NOFOLLOW and passed by its descriptor where the
  debugger takes one; the debugger run as the core's owner (or nobody),
  with a time and a memory limit (rctl or setrlimit).
- Faults whose owners are not held to what they watch yet (agent
  0.280.0 holds the prober's, the links', the sampler's, the crashes'
  and luxuria/birdwatch.c's by fault_reconcile()): sdbird.c's (bfd,
  bird-instance, bgp-neighbor of SD-WAN's instances, its was_up() in
  memory), sdids.c's, smtpd.c's, sa.c's key-rotation; each the same
  way, at its start and when what it watches changes.
- The kernel message buffer's end found by its contents
  (gula/kmsg.c): when the ring wrapped and the kernel said the last
  line read again, which of its places is the old one stays a guess (the
  last no later than where the read before ended).  kern.msgbuf says no
  sequence; a reader of /dev/klog, or a sysctl that tells the ring's
  write sequence, would end the guessing.
- The routing socket record.c reads carries every routing message:
  FreeBSD has no ROUTE_MSGFILTER (OpenBSD's) to have the kernel send
  RTM_IPFWLOG alone; the others are read and passed over.
- arcana-enrol's -f pins the CA by the command the console shows; the
  token itself does not carry the fingerprint (it is 32 random bytes,
  looked up as they are): a token that does would let a host enrolled
  from the bare token check its CA too.
- To decide (the user's): BIRD that stops answering while a safe
  change waits leaves the unconfirmed file in place, as bird.c says
  ("one that died is not undone after"), so BIRD's next start reads a
  change nobody confirmed.  Safe mode takes an unconfirmed change back
  elsewhere: put the file back here too?

- One EventSource a page instead of three (sse.c: the fleet's stream,
  arcana-host's stats, arcana-jobs): every tab of the console shares
  the browser's one HTTP/2 connection, and each page holds its event
  streams and its WebSocket open on it for good.  The design: a GET
  /restconf/streams/page/json?fleet=1&sub=<id>,<id> (rcstream.c) that
  starts the fleet's stream and takes the page's established
  subscriptions on one reply, one thread, each event named by what it
  is of ("event: fleet", "event: sub-<id>"; its id the event time
  prefixed by the same, so Last-Event-ID replays each); a subscription
  established later, or one ended, said to it by a POST naming the
  page's stream (its id from the reply's first comment line) rather
  than a new GET; bridge.js's arc_sse_open/arc_sse_close then add and
  remove a name on the one EventSource, arc_on_sse unchanged.  The
  rcs threads already hold one host list each; the change is that one
  rcs carries several sources (rch sets) and the keep-alive and lost
  events are the reply's, not each source's.

## Not yet run for real

Written and tested with stand-ins only:

- The map with a real vnet jail as a node.
- Suricata's packet profiling: the VM's Suricata is the port's, built
  without `--enable-profiling`; packet_stats.log is parsed from its
  format as util-profiling.c writes it (8.0), with files written by
  hand.
- A jail's share of the CPUs and its memory from rctl_get_racct(2): the
  lab VM's kernel has kern.racct.enable off, and turning it on needs a
  reboot; what is read when it is off is run for real.
- The switch to SCTP from the page (the API is run for real, between a
  console and an agent on one machine).
- SD-WAN: the steering by BFD on the lab, resource faults; DNS sent to
  the service's resolver by ipfw `fwd` (ipfw takes the rule; no query
  has gone through it); DHCPv6 at a UNI (dnsmasq's enable-ra) and the
  unmake of rtadvd and dnsmasq; SLAAC on a UCS, a UCS in a VRF, BGP
  with the underlay.
- The Security section (URL filters, Antivirus, IDS/IPS) without
  SD-WAN, with the real plugins.
- Suricata's interfaces' queue interrupts (hw.intrnames, cpuset -x) on
  a NIC with RSS queues: the lab VM's interrupts are virtio's, named by
  no interface.
- Firefox: the console is tested in headless Chromium only.
- The install offer on a real phone: Chrome's prompt on Android, the
  wording for Safari on iOS and for Firefox.
- A login from an Android app named in web.conf's android block, on a
  real phone: the tests sign as Credential Manager would, with its
  origin (android:apk-key-hash:...), and read
  /.well-known/assetlinks.json, but Android has not been seen to accept
  the file or to sign for the console's rp_id.
- Notifications on a real phone. A message sent with the console's code
  is delivered to headless Firefox through Mozilla's push service;
  Google's service accepts the console's signature, but the Chromium
  build the tests run cannot receive from it.
- `arcana-enrol -s` on a real host, the container image, and the update
  check against GitHub's live feed.

## Verified for real

- A service written as L3NM through RESTCONF alone (PLAN-SDN-YANG
  4.10.1; 2026-11-06, the lab VM as root, console 0.380.0, agent
  0.248.1, the root test console_test:sdwan_l3nm_lab): two vnet jails,
  each an agent's host, an epair(4) their Internet and another their
  UNIs.  The UCS and the edges PUT at `ietf-l3vpn-ntw:l3vpn-ntw` with
  If-None-Match, the service PATCHed with If-Match (a stale tag 412);
  branch's access placed on b's UNI, a free SAP of
  `ietf-network:networks`, by `arcana-console:sdwan/attach`.  Planned
  and applied at `sdwan/plan` and `sdwan/apply`, rc-conf-files
  accepted: gre(4) both ends with their /31 in FIB 1, both UNIs
  addressed in it, hq's static route, kept in Arcana's rc.conf file; a
  ping through the tunnel and one UNI to UNI.  Read back as `ietf-vn`:
  one VN, its member hq to branch, the gre tunnel its underlay, up and
  selected by the edges' probes; as SAP: both UNIs the service's,
  made, op-up, not free.  Exported at `sdwan/document` and PUT back:
  the L3NM node for node as it was, the document the same but its
  version, a second plan making nothing.  Taken away by DELETE with
  If-Match: the jails' addresses, tunnels and routes as before, the
  SAP free again.
- STAMP against two other implementations (PLAN-SDN-YANG 5.1.9;
  2026-11-11, on the loopback, stamp d983c96, agent 0.276.0):
  - teaparty (Rust, GPLv3, 7fb2bde), a full STAMP sender and
    reflector.  Its sender to stampd: the base, an SSID, the
    Timestamp Information, Class of Service, Location, Extra Padding
    and HMAC TLVs each answered, as long as asked, every field as it
    reads them; the authenticated mode verified under a shared key, a
    wrong key dropped and counted.  stamp(1) to its reflector,
    stateless and stateful (told so by the first reply): the base and
    each TLV ours sends answered; its Direct Measurement not known
    (none said, rightly).  Found and fixed in stamp: the TLV flags
    (ours sent U 0 and the reflector left the sender's flags, which
    cancelled out between two of ours; RFC 8972 4 wants a sender's U
    1, a reflector's U, M and I 0 for what it knows), and a Location
    port the reflector leaves 0 taken for NAT.  Theirs: our error
    estimate (scale 32, multiplier 140: 140 s) read as 2.56 s; TLVs
    in the authenticated mode sent without the HMAC TLV RFC 8972 4.8
    asks for (ours marks them I, as the RFC says).
  - twampy (Python, BSD-3-Clause, 885b986), TWAMP Light (RFC 5357
    Appendix I).  Its sender to stampd at 44 octets, stateful: every
    packet answered, delay each way; at its default 22 octets none,
    the 44-octet floor against amplification.  stamp(1) to its
    reflector, either mode asked: every packet answered (it pads the
    reply to 46 octets of its own zeros and leaves the Sender TTL 0,
    TWAMP Light's ways; ours takes them).

## Known limits

- libwebsockets 5.1 ends a whole HTTP/2 connection (GOAWAY
  PROTOCOL_ERROR, "Another stream not allowed", lib/sansio/h2/http2.c
  in lws_h2_parse_frame_header()) for a HEADERS frame that would open
  one stream past SETTINGS_MAX_CONCURRENT_STREAMS; RFC 9113 5.1.2 has
  it a stream error, and REFUSED_STREAM tells the client to send it
  again.  A client sends its first requests before it has the server's
  SETTINGS, so with libwebsockets' 24 a browser with more waiting lost
  every new connection; the console allows 100 (web.c, H2_STREAMS),
  what clients take for granted till then.  What would change in
  libwebsockets: there, refuse the stream as lws_h2_refuse_stream()
  does for a full header pool (RST_STREAM REFUSED_STREAM, its block
  decoded into the sink for the HPACK table, its sid recorded closed),
  and drop the same test in __lws_wsi_server_new(); a stream that is
  closing (flushing what waits on the connection, or its completion
  put off behind it) to count no more once its END_STREAM is out.  And
  each new stream queues a window update (lws_pps_schedule()), 50 of
  them at most before it ends the connection with ENHANCE_YOUR_CALM:
  a frame's worth of new streams beyond that would want the window
  given by SETTINGS_INITIAL_WINDOW_SIZE rather than per stream.  Not
  patched here: the port's.

- A query argument's value with an "=" in it (encoded %3D, or even
  %253D) comes to the console cut at it: libwebsockets' argument
  parsing.  So a read below a host's entry takes no XPath
  filter; the filter is arcanactl get -x's and cblink's.  To look at
  in lws's parser, or read the raw query from :path ourselves. The
  same parser decodes the path's %-escapes before the console sees it,
  so RESTCONF cannot name a list entry whose key has "/" or "," in it
  (RFC 8040 escapes them as %2F and %2C).

- FreeBSD 16-CURRENT: an interface given an IPv6 address in FIB 0,
  moved to another FIB (ifconfig fib), then destroyed, leaves its
  link-local prefix route (fe80::%N/64) in FIB 0 on an interface index
  that no longer exists (netstat shows "---"); route(8) cannot delete
  it, the index not resolving.  The detach purges the interface's FIB
  at that time, not the one its routes were added in.  The collectors
  show such a route with no interface.  A FIB set before the addresses
  avoids it.  For a kernel fix (in6_ifdetach / rt_flushifroutes over
  every FIB).

- NAT64 (nat64lsn) through a vnet jail answered only with
  net.inet.ip.fw.nat64_direct_output=1: with 0, the translated replies
  are counted as "discarded due to some errors" and go nowhere.  Not
  looked into further.  With the well-known prefix 64:ff9b::/96 an
  IPv4 address that is not global (RFC 1918, the documentation
  ranges) is translated only with allow_private.

- FreeBSD 16-CURRENT, if_geneve: geneve_init() marks the softc
  running (geneve_init_complete()) even when it failed to set up its
  socket, so a failed start is never retried until the interface goes
  down and up again.  The first geneve of a network started by an
  address given to it (SIOCSIFADDR, under in_control) fails so; one
  brought up first does not.  The agent brings a geneve up as it makes
  it, and keeps "up" in its rc.conf line.  For a kernel fix.

- RFC 4364 VPN routes are not written for the control plane: the
  FreeBSD port of BIRD 3 does not build its l3vpn protocol
  (docs/PLAN-119-SASE.md, 119-5).
- IPsec: a FreeBSD kernel bug (sys/netipsec/xform_esp.c): with an AEAD
  cipher (AES-GCM, ChaCha20) and ESN, esp_input adds the ESN high bits
  to the separate AAD only when the SA has a replay window (wsize !=
  0), while esp_output adds them whenever the SA has replay state; an
  SA without a window (setkey without -r) sends an ICV over four more
  bytes than the receiver checks, and every packet is a bad
  authentication. The agent sets -r 128 on every SA, which is right
  anyway (R47), and then GCM with ESN works; worth a fix upstream (the
  same test on both paths).
- SCTP to an address on lo0 from another host is answered only by a
  kernel that scopes SCTP by address (net.inet.sctp.ignore_loopback_iftype,
  a patch not upstream); a stock kernel counts such an address out of
  a non-loopback peer's scope (sctp_is_address_in_scope()) and sends
  no INIT-ACK.  That is the kernel, not Arcana.
- The standard models have no place for a vxlan's or geneve's VNI and
  ends.  ifconfig(8) does not set an ipsec(4) interface's ends from
  addresses that are not the host's, and says nothing (exit 0).
- In a vnet jail, devfs hides bpf, which dnsmasq's DHCP and dhclient
  need; no default ruleset unhides it.  Netgraph in a jail needs the
  jail to allow its sockets (`allow.socket_af`) and the node types
  loaded on the host: a jail cannot load a module.

- The GitHub workflow: the images it builds on
  (ghcr.io/spmzt/freebsd-emscripten, cblink) carry a 16.0-CURRENT
  userland, and vmactions/freebsd-vm boots 15.1 at most, so inside the
  container head(1), tail(1) and the like die on casper ("Invalid
  pdflags at fork") and the agent's test suite fails there while it
  passes on a 16.0 host; the same skew is the likely cause of the
  ipsec and vnet cases' garbled arguments.  Until the images' userland
  and the VM's kernel match, or the tests have a kernel of their own,
  the build cannot go green; it runs by hand only.

- The build of the agent on a host runs as `nobody`, in a directory
  `nobody` owns and that outlives the build, and `make install` of a
  console update then runs as root from that tree. Any other process
  running as `nobody` on that host can change what is built. A user of
  its own for the build, a fresh directory for each, and the host keys
  and deploy key kept where the build cannot write would close it.
- A security key is asked for its owner's presence, not for a PIN or a
  fingerprint: keys without either still work, and a key found works
  for whoever found it. Sessions are not tied to the key they were made
  with: one made with a key since removed lasts until it ends.
- Somebody who can log in can make the console connect to port 443 of
  any host by naming it as a push service's address; the certificate
  must be valid for the name, and nothing of the answer is shown but a
  status and the start of an error.
- A change made in safe mode that fails half way (the MTU set, the
  description refused) reports the failure and leaves what was done.

- There is no web terminal in the console.
- Luxuria in the agent is the plugins, BIRD among them (WireGuard's
  `wg` is the base system's and Invidia's); what reaches outside (the
  release check, notifications) is the console's.  A plugin is still
  built into the agent and the page: what makes it one is that it is
  there only where its program is installed.
- The agent runs no jls(8): a jail by name is read with jail_getv(3),
  every jail with jailparam_get(3).  The unprivileged tests preload
  libfakejail.so into the agent they start, whose jail_getv answers a
  lookup by name or jid from a file of the test's; the list of every
  jail is still the host's.

## Authorization (console 0.429.0), left

- The SD-WAN document and the L3NM are one for the whole fleet, so a
  user of a tenant is refused them (and the virtual networks made of
  them) rather than shown a part.  Tenant-scoped services need a
  design: a document a tenant (its SWVCs, end points and edges among
  its hosts), the shared underlays and the provider's edges between
  them, and who applies what of whose.
- `login/begin` lists every key's id to anyone who asks (non-discoverable
  keys need the list); a sign-in by user name first, or discoverable
  keys alone, would give out none.
- A follower's `cluster_save()` returns 0 once the leader committed,
  whether or not this node applied it in time (`wait_applied()` timed
  out): a read here right after may still see the old copy.
- Each node of a cluster writes a setup token of its own while the
  console is not set up; one, the leader's, would be enough.
- The unix listener is 0666 (the console's own user connects to it):
  its clients still need a session or a token, but all count as one
  address to the sign-in throttle, and the threat feeds learn no
  user's address from them (`feeds_signin()`).
- Directory users are fleet-wide (console 0.432.0): a user the
  directory keeps is of no tenant, and a role whose directory group
  has them, with "*" for its hosts, gives them every tenant's hosts.
  The design: a tenant beside the group in the mapping (a role's
  `ldap_group` and an `ldap_tenant` with it, a leaf of the role in
  arcana-console, its .sid renumbered), `users_ldap_sync()` making the
  user of the tenant of the groups that admit them (refused when two
  tenants' groups do, said why), and the page's Roles form a field
  for it.  Until then an owner gives directory groups roles that name
  their hosts, not "*".
- Setting one's own password needs no current password and no fresh
  key: a session left open sets it.  It is to ask for the current
  password, or, from a key's session, a key assertion made for it (a
  challenge of its own, as login/begin's); the page's password form
  then asks for one.
- The Telegram alerts' sender host (Settings, `telegram_via`) is
  asked as the console for every message, a workflow's notify step's
  too: a workflow's error names that host to an operator who may not
  read it.
- Adding a host whose URI is another's is refused saying so, the host
  unnamed: that a URI is registered is told to whoever may add one.
- bcrypt runs on the loop still when a password is set (setup, Settings,
  AAA): the sign-in, which anyone may ask, runs in a task.
- Adding a host resolves its name on the loop to compare it with the
  agents registered (`same_agent()`); a name that takes the resolver
  long holds the loop that long.
