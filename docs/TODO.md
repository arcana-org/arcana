# TODO

## To do

- ipfw's table swap (IP_FW_TABLE_XSWAP) of two `number valtype dscp`
  tables corrupts their values, and a flush of them then panics
  (`Refcount is 0 on kidx`, unref_table_value): a kernel fix, the
  user's.  Alternate marking (PLAN-SDN-YANG 5.5) is refused until then
  (agent 0.292.1, console 0.443.1); agent_root_test:sdwan_altmark_lab
  skips.  The plain-ipfw reproducer is in the arcana-lab VM's
  /root/repro.
- IPFIX export in ng_netflow(4), kernel work and the user's:
  ng_netflow exports NetFlow v5 and v9 only (both hooks at once,
  nothing else); pflow(4) has IPFIX but serves pf.  The flow records
  (PLAN-SDN-YANG 5.6.1, agent 0.292.0) take v9.  An expired flow
  waits in a partly filled export datagram until it fills or the node
  shuts down, with no timer to send it; a flush belongs to the same
  work.  The flow records' collector is IPv4 alone: ng_ksocket's inet
  form; an IPv6 one needs its generic sockaddr form.  And they are a
  host's edge's alone: ng_ipfw makes its node in the host's network,
  none in a vnet jail's; agent_root_test:sdwan_flowexp_lab runs in the
  VM round (it skips in a vnet jail).
- The archive (PLAN-SDN-YANG 5.6.3, gula/archive.c; the page's long
  run, www/arcana-ui/src/archive.c): the archive's settings (enabled,
  budget, each class's step and retention) have no form on the page
  yet, only RESTCONF and history.conf.  A day's file is read
  whole into memory at the start and by a read (64 MiB at most), so a
  budget far above the default with a thousand targets at a 10 s step
  can make a day's file too big to be taken up again.
- The SDN and YANG redesign: docs/PLAN-SDN-YANG.md. Open decisions:
  D-5, D-11, D-12 (D-6 taken: a FIB per vpn-node).
  To do, the datastores first, to the safety design decided on
  2026-10-28 (in the plan, 2.3): 2.3.x (candidate and
  running), 2.3.5 the rc.conf.d
  fragments rendered (the agent edits rc.conf through sysrc(8));
  RESTCONF (Y-4).
  The interim family is gone (3.8, 0.238.0/0.336.0): every operation
  is a YANG module's, its task's { } Schema panel showing the
  module's tree.
  For the user: the CORECONF draft's examples number some
  ietf-interfaces items otherwise than SIDS.md.
- MEF 138's SENs of the daemons (agent luxuria/sdblock.c), what is
  left: a PDNS's A and AAAA entries and its No-match are unbound's
  response-ip, which logs only its inform actions (none of which
  answers NXDOMAIN), so they are told by no SEN; a URLF match of a
  named list (a file of Squid's) is told as Block without its entry; a
  DNF name with a * inside that Squid ends is told as Block, Quarantine
  or not.  The log lines read are unbound's, from its source
  (log-local-actions, rpz-log), Squid's in the arcana format, and
  c-icap virus_scan's "VIRUS DETECTED"; only stand-ins wrote them in the
  tests: what a real Squid logs for an ssl_bump terminate is to be
  checked on an edge.
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
  the agent's fault types (gula/yalarms.c, kinds[]), by hand, for their
  labels; since console 0.442.2 a type a host's alarm inventory (RFC
  8632) has and the page does not name has a row too, by the host's
  description.  The console's own settings have no { } Schema panel: no
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
- The prober's engine (agent 0.288.0, gula/probe_engine.c) still has
  the steering made again on its own thread when a target's state
  changes (sdwan_probe_changed(), ipfw run by invidia/sdwan.c), as the
  prober's thread did before: its worker could take it, the changes in
  their order.  A jail's echo targets keep a socket each, made by the
  helper inside the jail: one a jail's FIB and family would need the
  helper to hand one socket to several targets.
- The agent's allocations (work.c's wcalloc, wmalloc and the rest, and
  err(1) on a failed pipe2(2) or realloc(3) in ira/exec.c) end the
  root daemon when memory runs out, a change half done with it; a
  failure of one request's alone, said, is to come.
- Faults held to what they watch (agent 0.287.0 adds sdbird.c's,
  sdids.c's, smtpd.c's and sa.c's to the prober's, the links', the
  sampler's, the crashes' and birdwatch.c's): the tests seed faults an
  agent before left and see each owner's first view clear them; a
  subject removed while the agent runs is tested for none of the four
  (an SD-WAN BIRD instance or a Suricata needs the real programs), nor
  an IDS instance or a BGP neighbour whose cause went over a restart.
- The hosts' default for reads stays permit (Settings, AAA, Roles has
  the default for actions alone, agent 0.287.0): read-default deny
  would want a permit of every data node a viewer reads today, and no
  list of the agent's names them (nacm-allow names actions and the
  text leaves); the page and RESTCONF would have to be gone through
  for a viewer node by node first.
- A viewer's service read is what the agent last saw (ira/services.c,
  every five minutes and every operator's read): a service started or
  stopped by hand shows so to a viewer within five minutes, not at
  once.
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
- net.inet.tcp.bind_all_fibs (and udp's) is 1 by default in main (a
  change to 0 was reverted on 2026-10-29 and may come back).  Arcana
  reads both ways: the BMP stations listen a port apart per FIB for it
  (gula/bmp.c), but c-icap's place (sdconf.c icap_conf_render) and its
  comment take 0 (nothing in a service's table can bind the loopback),
  and with 1 a service's table could reach a Security-section c-icap
  on the loopback.  To decide: set the value Arcana needs on an edge
  (rc.conf.d), or make the c-icap rendering safe under 1.
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

- Left of the review after agent 0.285.0: the speederv2 key is in the
  relay's command line (speederv2 takes it there alone, as far as
  could be told: no config-file option known, the program not on the
  build host) and in the file sysrc(8) writes the flags to, /etc/rc.conf
  first of rc_conf_files, 0644.  To come: the relays' flags in
  rc.subr's own file for the script, /usr/local/etc/rc.conf.d/
  arcana_relay, 0600 (load_rc_config arcana_relay reads it), read
  there first and from rc.conf for a relay an agent before wrote, moved
  at its next conf (the read, the write, the safe undo and the move of
  speeder.c, beneath a jail's root for a jail's, and the console's
  tests that look in rc.conf).  The page has no field for an agent
  downgrade (the API's `downgrade`).
- The console signs an update's program alone for an agent without
  `signed-update` (zprog.h): the one compatibility the update path
  keeps. It goes once no deployed agent predates 0.284.0.
- The build of the agent runs as `_arcanabuild`, a user nothing else is,
  in its own 0700 directory, root taking the program and the deploy
  key's public half through a pinned directory (agent 0.284.0). A
  console update's `make install` still runs as root in the build
  user's tree, held to the commit fetched (agent 0.285.0,
  tree_unchanged()); what an object directory holds (a `.depend` file
  make reads, among them) is still the build user's.  The staged
  install that would close it: the build user runs `make install
  DESTDIR=<stage>` with `-DNO_ROOT` and a METALOG (install(1) `-U -M`),
  which the tree's makefiles and the submodules' (cblink, jailconf,
  stamp) do not do yet for their own install targets (`beforeinstall`'s
  `${INSTALL} -d`, the rc.d scripts, the page's files); root then copies
  out of the stage through a pinned directory, each name O_NOFOLLOW, a
  path a METALOG line names only, under PREFIX, LOCALBASE's etc/rc.d,
  WWWDIR or the man pages and nowhere else (no absolute name, no "..",
  no link out), modes and owners from the METALOG, no setuid or setgid
  bit at all (Arcana installs none), each program's SHA-256 logged.
  The host keys and the deploy key still sit where the build user
  writes; the directory still outlives the build.
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
  them) rather than shown a part, and so is a token its maker's
  (console 0.434.0).  Tenant-scoped services need a
  design: a document a tenant (its SWVCs, end points and edges among
  its hosts), the shared underlays and the provider's edges between
  them, and who applies what of whose.
- The prefix lists and the threat feeds' definitions are every
  tenant's alike: refused to a tenant's user and to their tokens
  (cnodes.c's T_ALL, console 0.434.0, the tenants plan's T-0.1) until
  they are a tenant's own.
- A cluster's audit trail and SENs/SANs are each node's own, each
  record naming its node: one trail would want appends through the
  log (an entry kind idempotent by a record id).
- The SD-WAN apply's lock of a cluster is renewed before each step's
  jobs, for two minutes: a step that waits longer than that for its
  jobs loses it, and the apply stops at the next step rather than run
  beside another.  The schedulers check their lease each tick, not
  again before each side effect.
- A unix listener's client is known by its uid (console 0.434.0); the
  threat feeds protect addresses, so a local user signing in is not one
  of theirs (`feeds_signin()` keeps IP addresses alone).
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
- The Telegram alerts' sender host (Settings, `telegram_via`) is
  asked as the console for every message, a workflow's notify step's
  too: a workflow's error names that host to an operator who may not
  read it.
- Adding a host whose URI is another's is refused saying so, the host
  unnamed: that a URI is registered is told to whoever may add one.
- Adding a host resolves its name on the loop to compare it with the
  agents registered (`same_agent()`, also an enrolment's `servers_add()`
  and a move); a name that takes the resolver long holds the loop that
  long.  To do: the hosts' change resolved in a task before it is
  judged on the loop.  The other blocking calls left on the loop:
  store.c's and audit.c's fsync(2) of each document and audit record
  written (bounded by the disk; a slow pool holds the loop), pki.c's
  certificates written on the loop (the CA's actions), and the
  directory's settings test where it runs on the loop (ldap.c dial()).
- The console's confirmation of a safe job a workflow polls
  (`hosts_job()`) is said as the job's own user since 0.434.0; no test
  drives a workflow's safe job by a token yet.
- HTTP/2 streams (`h2_streams`, default 100): nghttp2's h2load, which
  sends a first flight whole, has the connection ended by libwebsockets
  from 48 streams at once (its 50 queued window updates); browsers and
  curl pace theirs and 100 pass.
