# Updating Arcana

The console asks GitHub's release feed every six hours and shows a
banner when a newer version is out; `update_check = false` in `web.conf`
turns that off. It does not replace itself, since it runs unprivileged:

- the container image carries `io.containers.autoupdate=registry`, so
  `podman auto-update` (from cron, say) pulls a newer `ghcr.io/arcana-org/arcana`
  and restarts the container;
- a native install is updated with `pkg upgrade arcana`, or
  `make install` from a newer tree, then `service arcana_console restart`.

Certificates stay valid across updates.

## The page and the installed app

The page keeps its files in the browser, through a service worker, so
that it opens without a network. It looks for a newer set on the
console whenever it comes back into view, which for the app installed
on a phone is every time it is opened, and every half hour while it
stays open. When there is one it takes it and loads itself again; there
is nothing to reinstall. The new files are fetched from the console
itself, past the browser's own cache.

## Updating the console from the repository

With a repository set (`agent_source`, under **Settings**), the header
of the host the console runs on, the one added by its local socket
(`unix:/var/run/arcana-agent.sock`), has **Update console**. The agent
there clones the repository, builds all of Arcana as the build user
(`_arcanabuild`, below), runs
`make install` as root over what is installed (the console's module,
the page, the agent and the tools), and restarts the `arcana_console`
service and then itself, `arcana_agent`: the console and the agent of
one host are of one version, and read each other. Updating by hand,
restart both too. The agent the console then sends to the other hosts
is the one installed with it, unless one a host built for it is newer.
The page reconnects by itself, still logged in: the console keeps its
sessions over a restart. When the console answers with another version
than the page was loaded from, the page loads itself again, after
letting its service worker take the new files. A repository over SSH
asks for its host key as a build does. From a shell: `arcanactl
console-update [-y] [-i key] repository [ref]`.

The build's programs run with the build directory
(`/var/cache/arcana-build`) as their home: emcc keeps its cache there,
and builds its system libraries into it the first time, which takes a
few minutes more.

`make install` runs as root in the tree the build user built, so before
it does the agent holds the tree to the commit it fetched (agent
0.285.0): no process of the build user's still running, `git status`
(as the build user) saying nothing changed, `HEAD` the commit fetched,
and no file changed since the fetch but beneath an `obj` directory;
otherwise nothing is installed, and the reply says what changed. A
build whose makefiles write into the source tree is refused so.

It needs on that host what building Arcana needs (see the README),
Emscripten included, and its settings in
`/usr/local/etc/arcana/config.mk`. A console in a container is updated
with its image instead. The agent on that host is installed too, and
runs from its next restart.

## Updating the agents

The console marks a host whose `arcana-agent` is not the one it has,
and can update it: **Update agent** beside the version on the host's
page, or **Update N agents** on the fleet page for every such host.
Builds are told apart by the program's SHA-256, which each agent
reports, so a rebuilt agent of the same version counts as another. The
console sends the `arcana-agent` installed with it (`agent_binary` in
`web.conf` names another), by arcana-agent's `update` action. It sends
the program compressed with gzip (the base system's zlib) to an agent
that says it takes it so (`gzip-update` in arcana-host's agent
features), and as it is to an agent before: within the agent's cblink
frame, 8 MiB less 64 KiB, which the agent (6.1 MB) fits, and compressed
it is a quarter of that. Each host

1. inflates a compressed program, to no more than the size sent with it
   and never past 32 MiB (`max-program`),
2. checks the program, inflated, against the SHA-256 sent with it, and
   against its signature by the console's CA key (over a network
   connection, and from the socket's group, the console's user; root,
   or the agent's own user, on the local socket is root already),
3. writes it beside the installed one and runs it with `-V`: a program
   built for another machine or FreeBSD version does not run, and is
   dropped,
4. puts it in place of the installed one, which stays as
   `arcana-agent.old`.

An agent with no features in arcana-host (0.236.0 and before) takes
the program as it is, within its frame. Once the agent is bigger than
that, such a host cannot be sent it, and the console says so; `pkg
upgrade arcana` there updates it instead.

### Jails: cores, relays, manual SAs, signals; agent 0.325.0, console 0.469.0

- crashes lists each running jail's cores, found beneath its root where
  kern.corefile puts them (each with "jail"), and reads a jail's
  backtrace with the jail's own program and libraries (arcanactl -j
  <jail> crashes backtrace <core>); a jail's core only of a crash the
  kernel said was in that jail.
- The FEC relays' rates in the history and archive come from each
  jail's log too, named <jail>:<tag>; a jail's relay may be changed in
  safe mode, undone in the jail.
- ipsec-sa takes a vnet jail (arcanactl -j): its SAs and policies by
  PF_KEY in the jail's network, its key pair and state kept on the host
  as <interface>@<jail> (so named in the sdwan read, the sdwan-key
  event and the key-rotation fault).
- A jail's process signalled or reniced from the Processes page names
  its jail in the job.  arcanactl: geom, zfs, zpool, gpart, cam, mount,
  umount, swapon, swapoff, iscsi and hast refuse -j before sending.
- Update the agent and the console together (arcana-jobs 63120-63121,
  arcana-crashes 85222-85224).

### Services of a running jail; agent 0.324.0, console 0.468.0

- arcana-services' read action on arcana-jails' jail lists a jail's
  rc.d scripts, read in the jail by the agent attached to it, with
  status from the jail's own service(8) (`service -j`).  The
  service-action and service-config jobs take `jail`: the script runs
  in the jail, and enable, disable and the variables go to the jail's
  rc.conf (`sysrc -j`), put back in safe mode.  The event service-state
  carries `jail`.  The Services tab picks the host or a running jail,
  and a jail's page links to its services.  `arcanactl services -j
  <jail>` and `service -j <jail> <name> <verb>`.
- Update the agent and the console together (arcana-services
  97100-97131, arcana-events 94922-94924, arcana-jobs 63116-63119).

### BMP's station reached in any FIB; agent 0.323.0

- A BIRD instance's BMP station in a FIB other than 0 (on the host, or
  in a vnet jail) now has 127.0.0.1 by lo0 in that FIB: the agent puts
  rc.d/routing's loopback route there when the FIB has none (one made
  after boot, or a vnet jail's when net.add_addr_allfibs is 0), where
  BIRD's BMP session could not connect before.

### Running reads no state (cblink 0.2.30); agent 0.322.0, console 0.467.0

- A read of running or the candidate no longer runs the handlers of
  state-only nodes (config false, or containers holding only state):
  an edit's read of running no longer runs the storage read (zpool,
  zfs, camcontrol, smart) and the other state reads twice, and a state
  read that fails cannot fail an edit.  Operational reads are as
  before.

### Mapped terminal logins; agent 0.321.0, console 0.466.0

- A host's admin can map a console user to an account of the host, or
  of one of its jails (Terminal tab, Mapped logins; arcana-console's
  host terminal-login): that user's Terminal then runs `login -f` of
  the account, no password asked.  The host must allow it in
  /usr/local/etc/arcana/terminal-users, root's and mode 0600, every
  directory above it root's and not group or world writable; lines
  `host|jail:<name> <account> [+root] <console user>...`, uid 0 only
  with +root.  Without the file nothing changes (mapped logins are off,
  and the page says so).  The checks login -f skips are made by the
  agent: expired or locked accounts, a nologin shell, /var/run/nologin
  (not for uid 0), the login class's limits, an expired password.  A
  session counts only once utmpx shows exactly that account; the file
  is checked again every 2 s and a session it no longer allows is hung
  up, as one whose mapping is removed is within a second.
- Changing a mapping or the per-host terminal-prompt (allowed|never)
  needs a security-key session of the host's admin and If-Match on the
  request; both are audited.  The page's host forms (mute, rollback
  timer, readdress, repositories) write their own nodes by YANG Patch.
- New stream command terminal-as (7), nacm:default-deny-all.  The
  operator rule-list gains the protocol-operation rules terminal and
  terminal-as only on hosts whose exec-default is permit.  New fault
  empty-password (Major): a count of the accounts that log in with no
  password, their names only in the host's auth log.  New agent options
  --terminal-users (none turns it off), --terminal-getent,
  --terminal-nologin.
- Update the agents before mapping anyone: an older agent answers "this
  host's agent cannot do mapped logins".

### RFC 9061's IKE-less lists by PF_KEY (6.2.4); agent 0.320.0, console 0.465.0

- ietf-i2nsf-ikeless's ipsec-ikeless is served: running holds the
  controller's SAs and policies, kept in ikeless.cbor beside the agent's
  files (0600, the keys in it), each put in by PF_KEY as it is
  configured, an edit changing what differs alone and undone whole when
  a step is refused; the operational datastore lists every ESP SA and
  policy of the host's network, the controller's by their names, the
  rest (setkey's, an IKE daemon's, an interface's, the ipsec-sa job's)
  read only as esp/<destination>/0x<SPI> and spd/<id>.
- The notifications name the controller's entries by their names, and
  sadb-acquire's local prefix is the policy's source.
  arcana-ikeless-deviations is revision 2026-11-19: the lists are no
  longer deviated away, the per-SA replay statistics FreeBSD lacks are.
  net.key.preferred_oldsa is set to 0 when an SA is put in.  At the
  start the controller's policies are put back; its SAs the kernel lost
  leave running.
- Network > Base system > IPsec shows both lists, Arcana's entries with
  Edit and Remove, + SA and + policy by the model's form.  The ipsec-sa
  job is unchanged; its clear leaves the lists' SAs.

### SSL inspection, phase 2; agent 0.319.0, console 0.464.0

- An SD-WAN MBSF bound to zones is SSLproxy's: a zone whose only Squid
  function is its MBSF (no URLF, no MD+R, no DNF name with a `*`
  inside) has its TLS opened by SSLproxy (security/sslproxy, installed
  by the admin) instead of Squid's ssl-bump.  The apply issues the
  edge's CA from the tenant fleet's root where it has none, compiles
  the edge's sslproxy form (the zones' prefixes and UNIs), enables
  arcana_sslproxy and runs it in the service's FIB
  (arcana_sslproxy_fib).  Zones with a URLF or MD+R stay on Squid.  One
  service and one MBSF per edge; not a vnet-jail edge.  Install
  sslproxy on those edges before deploying.
- The inspection roots are the console's replicated document
  inspection-roots.json; a root made before in <datadir>/inspection/ is
  not read: press Renew on each edge's SSL inspection tab and have the
  clients trust the new root.
- New agent option --sslproxy-watch (default 30 s): set 27 is loaded
  again after an ipfw restart while SSLproxy runs.  A rule of SSL
  inspection's is any whose comment contains `sslproxy:`; the rc script
  also refuses to load when another set has a rule at 7.

### Suricata's forms in the module; agent 0.318.0, console 0.463.0

- arcana-sdwan's Suricata instances (ids-instance), SD-WAN's and the
  Security section's, have their form (spec) as the module says it: a
  container of ids-form (SIDs 96 600 to 96 638), no longer JSON text;
  conf is now state, Suricata's YAML as the agent rendered it, shown
  under each instance on the SD-WAN page.  Suricata's YAML is no longer
  taken whole (arcanactl sdwan ids without a spec is refused).
- Update the agent and the console together.  Nothing to save again: a
  kept form loads as it is, its name, divert and stopped (the
  instance's own) left out of it.

### No pools without ZFS in the kernel; agent 0.317.0

- A host whose kernel has no ZFS (zfs.ko not loaded, a UFS root) reads
  its pools, datasets and snapshots as none, where the storage read
  failed and with it every edit of the running datastore ("reading it
  failed: Input/output error").

### Updates taken and builds sent compressed alone; agent 0.316.0, console 0.462.0

- The agent takes arcana-agent's update only compressed (program-size
  is mandatory) and always sends its build back compressed;
  arcana-agent's build input has no compress leaf any more (SID 83100
  obsolete).  No client sends otherwise since agent 0.312.0 and
  console 0.460.0.

### Service starts and stops told at once; agent 0.315.0, console 0.461.0

- A service started or stopped by hand (or by anything else) is noticed
  within a second or two: a running service's main process is watched
  for its exit (kqueue EVFILT_PROC), and a stopped one's pidfile is
  checked when the host's processes start and every 15 s; only the
  service that changed has its status run again.  The change updates
  what viewers read and is sent as the new arcana-events event
  service-state ({service, state, pid}, SIDs 94909 to 94921); the
  Services tab re-reads on it, and workflows can trigger on "a service
  starts" or "a service stops".  The services collector's first look is
  10 s after the agent starts.  Services with no pid in their status and
  no pidfile are checked every 60 s.

### RFC 9899's ACL actions; agent 0.314.0

- RFC 9899's ACL actions are compiled to ipfw (PLAN-SDN-YANG 6.1.7).  A
  rate-limit is a dummynet pipe of the ACE's own (pipes 41000 to 44999
  and 51000 to 54999 are now the ACLs', two generations swapped with
  the rules; SD-WAN keeps 3000 up).  An edit with a rate-limit is
  refused where dummynet is not loaded (the agent does not load it for
  ACLs) or net.inet.ip.fw.one_pass is 0.  log-action is the rule's `log
  logdst` (syslog, bpf, rtsock).  counter-action is a count rule per
  name, read back by the new module arcana-acl (SIDs 96 800) as
  acls/counters.
- Move any rule of yours that sends to a pipe in those ranges first; a
  host with pipes of its own in 41000 to 54999 should renumber them.

### BFD in the prober's steering, a jail's echo socket every FIB; agent 0.313.0

- BFD session changes no longer remake the SD-WAN steering on BFD's
  reader thread: they are counted into the prober's worker with the
  probes' state changes, so a burst of both is one ipfw run.
- A jail's echo sockets are made by the helper with their FIB set
  inside the jail (helper verb icmp-socket takes family:fib); while a
  jail's target is in a table other than 0 the jail gets an echo socket
  for every FIB (up to 16), as the host already did.

### Updates only compressed; agent 0.312.0, console 0.460.0

- The console and arcanactl send an agent update only compressed, to
  an agent that says gzip-update in arcana-host's agent features; an
  agent before is refused ("this host's arcana-agent is too old for an
  update by the console: update it by hand (arcana-agent's port or the
  package)"), and is asked for no build either.  `arcanactl
  agent-update -p` is gone.  Every agent since compressed updates
  takes them.

### SSL inspection by SSLproxy, phase 1; agent 0.311.0, console 0.459.0

- Security > SSL inspection (docs/notes/ssl-inspection.md).  SSLproxy
  is a plugin (`pkg install sslproxy` from the tab's button); Arcana's
  rc script `arcana_sslproxy` runs it (the port has none).  The form
  renders /usr/local/etc/sslproxy.conf, checked by `sslproxy -Q`.  The
  clients' traffic reaches it by ipfw `fwd` rules in set 27 at rule 7
  (staged in set 26), loaded at start and removed at stop; a host whose
  ipfw sets 26 or 27, or rule 7, hold rules of its own is refused until
  they are moved.
- The edge's CA key is made on the host; the console signs it with one
  root per tenant fleet, kept in datadir/inspection/ (new action
  hosts/host/inspection-ca); clients install that root once (download
  on the tab).
- New: job kind `sslproxy`, module arcana-sslproxy (SIDs 96 500+),
  arcanactl `sslproxy`, agent options --sslproxy-conf and
  --sslproxy-dir.  Update the agent and the console together.

### IPsec a part of Network's Base system; console 0.458.0

- The base system's IPsec (manual SAs and policies by PF_KEY, setkey's
  ipsec.conf) is no longer a section of the Network tab of its own: it
  is a part of Base system, the IPsec button in its row after
  WireGuard, at #/hosts/<id>/network/base/ipsec.
  #/hosts/<id>/network/ipsec now opens Base system.  strongSwan stays
  its own section.

### SD-WAN instances' forms in the module; agent 0.310.0, console 0.457.0

- arcana-sdwan's BIRD, dnsmasq, unbound and Squid instances have their
  form (spec) as the module says it: a container of bird-form,
  dhcp-form, dns-form or proxy-form (SIDs 93 227 to 93 299 and 95 600
  to 95 842), no longer JSON text; the text the agent rendered stays
  the conf state leaf, shown under each instance on the SD-WAN page.
- Update the agent and the console together.  The agent's kept forms
  now write a BGP community as "AS:value" (was [AS, value]) and a
  Security URL filter's listen as entries of an address (was words):
  after updating, apply SD-WAN again (fresh) on each edge and save each
  Security URL filter again; until then such an instance kept the old
  way is refused when the agent starts.

### Out of memory fails one request; agent 0.309.0

- A request or a job that runs out of memory fails alone, "out of
  memory", instead of ending the daemon: allocations that fail come
  from an 8 MiB reserve mapped at the start, the request runs no more
  programs, a YANG edit is taken back and a safe-mode job is undone
  ("out of memory: undone").  A pipe2(2) that fails fails only that
  program.  The daemon still exits if the reserve runs out too.  The
  new option --alloc-fault is for tests only.

### RFC 9899 matches, PF_KEY news; agent 0.308.0

- ACL matches (PLAN-SDN-YANG 6.1.6): RFC 9899's ipv4-fragment,
  ipv6-fragment, extension-header and TCP flags-bitmask are compiled to
  ipfw (frag's df/mf/offset, `ext6hdr frag` and `frag offset`,
  `tcpflags`, `ext6hdr`); alternatives become an or-block.  Refused,
  nothing loaded: IPv6's last fragment; its first fragment unless
  net.inet6.ip6.fw.permit_single_frag6=0 and deny_unknown_exthdrs=1
  (the admin's to set); the ECE, CWR, AE and reserved flags (so RFC
  9899 Appendix B.1 as written); mobility, HIP and shim6 headers; match
  and any at once.
- IPsec news (6.2.3): the agent registers a PF_KEY socket and tells the
  kernel's SADB_ACQUIRE and SADB_EXPIRE as RFC 9061's sadb-acquire and
  sadb-expire, and sadb-seq-overflow once for an SA without ESN whose
  counter nears its end (read every 10 s); names `esp/<dst>/0x<SPI>`
  and `spd/<id>` until 6.2.4.  New modules: ietf-i2nsf-ikeless
  (SIDs from 95 200) and arcana-ikeless-deviations (95 400).  Where
  ipsec.ko is not loaded the agent logs once and retries every minute.

### A remade STAMP pair reaches the far end; agent 0.307.0, console 0.456.0

- The agent tells a tunnel interface's pair made, turned or put back as
  arcana-events' new event sdwan-key (its key case: interface, public;
  SIDs 80199 and 94900 to 94908, a third range of arcana-events).
- The console keeps the far halves each edge's targets were given
  (sdwan-state's stamp_sent), reads the far ends' sdwan-key events each
  manager tick, and makes an edge's probes alone again by its own apply
  when a far end's half changed, said in the audit trail
  (policies-applied, "the console, by itself").  Until then, a tick and
  an apply, stamp-unauthenticated is raised as before.
- Update the agents and the console together: an older agent tells no
  sdwan-key, and an older console cannot read the event.

### Sign-in retried when unanswered; console 0.455.0

- A page that cannot reach the console as it opens says so ("Cannot
  reach the console") and tries again by itself after 1, 2, 4, 8 s,
  then every 15 s; a sign-in, enrolment or added key whose request got
  no answer is sent again up to five times, the page saying it tries
  again, before an error is shown.
- Security, IDS/IPS: an instance's own rules, thresholds and Lua
  scripts cannot be changed again while the last change is being
  applied (their buttons wait), where such a change used to be dropped
  with only a toast.

### Steering on the prober's worker; agent 0.306.0

- When a probe target's state changes, the SD-WAN steering is made
  again on the prober's worker thread, not a thread of its own, so ipfw
  runs no longer delay probes.  Changes that arrive while a steering
  runs are applied together in the next run, on the states they end in
  (the same tables as one by one); a burst that ends where it began
  runs no ipfw; a choice that came and went within one run is not
  reported as steer-changed.
- A vnet jail's echo targets share one raw socket per jail, FIB and
  family, made once by the helper inside the jail and handed over;
  replies are matched to targets by ICMP id and sequence.

### arcana-enrol checks the CA first; agent 0.305.0, console 0.454.0

- arcana-enrol first asks the console for its CA (`GET /api/enrol`, no
  token) and stops, the token unsent and still good, unless each root
  is one the token pins.  An `-f` given with a token must be one of the
  token's fingerprints, or nothing is sent.  Update the console before
  running the new arcana-enrol against it: an older console has no
  `GET /api/enrol`, and the new arcana-enrol stops there (the token
  stays unused).  Tokens already made keep working.

### The agent's own pidfile, stale pidfiles, /dev; agent 0.304.0, console 0.453.0

- The agent keeps /var/run/arcana-agent.pid its own: written back if
  removed or replaced (fault `pidfile` meanwhile).  After an update, a
  restart rc cannot do is done by the agent's pid when
  arcana_agent_enable is YES.  The fleet workflow's `agents` step waits
  up to 60 s for each host to answer as the new build and fails
  otherwise.
- Services: an enabled service rc says is stopped while its program
  runs is shown "running, its pidfile is stale" (arcana-services
  pidfile-stale, pidfile, pidfile-pid); the service-action job `pidfile`
  (arcanactl service NAME pidfile, Mend pidfile on the page) writes the
  found process's pid, after checking its jail and argv.
- Storage mounts carry arcana-storage `dev`: devfs mounts on /dev, the
  nodes they hide (devctl, mdctl, vmmctl) and whether devd answers; the
  page explains each and how to mend it by hand, with no button.
- New agent options for tests: --rc-subr, --dev, --devd-pipe.
- Update the agents with the console: arcana-services, arcana-storage
  and the service-action job gained leaves.

### pkg jobs that know their phase; agent 0.303.0, console 0.452.0

- pkg's silence watchdog knows pkg's phase.  While pkg fetches, silence
  past --pkg-idle (600 s) still stops it; once it has begun installing,
  the job's trace says pkg waits on a package's script (with what pkg
  printed last), and pkg is stopped only after three times --pkg-idle
  of silence (30 minutes).  After an upgrade, what is still pending is
  read from pkg's catalogue (pkg version -U), without asking the
  repository again (a jail that cannot reach it no longer waits a second
  watchdog).  A failed fetch's error carries pkg's lines of it (URL and
  reason).  A running job's read carries what its program has printed
  so far (the last 16 KiB).
- The host's packages read and refresh name its running jails on
  pkgbase (arcana-packages pkgbase-jail, new SIDs).  Beside "Upgrade the
  jails", the host's lanes and how many of its jobs run now; its confirm
  says both, and names the jails on pkgbase whose FreeBSD base moves
  with the upgrade.  The raw output says "running" for a program still
  at work.  The pkgbase list needs the agent of the same change.

### Manual IPsec in the core, console 0.451.0

- Manual IPsec (the ipsec-sa SAs and SPD policies by PF_KEY, setkey's
  ipsec.conf and the kernel's SPD) is a core section of the host's
  Network tab, IPsec (#/hosts/<id>/network/ipsec), shown whether or not
  strongSwan is installed: it is the base system's (pfkey(4), ipsec(4),
  rc.d/ipsec), not strongSwan's.  Its form gains the policy and
  unpolicy verbs.  The strongSwan plugin's section is now strongSwan
  (network/strongswan) and has IKE alone (swanctl, VICI); a link to
  network/ipsec now opens the base system's section.

### pkg asks its repository first; agent 0.302.0, console 0.450.0

- Before pkg update, upgrade, install, or a jail's base by pkg, the
  agent fetches the repository's meta.conf from where pkg runs:
  attached to the jail, the SRV record followed, PKG_ENV's proxies
  used, IPv6 and IPv4 raced.  If nothing answers within `--repo-reach`
  seconds (8), pkg is not started and the job fails saying what was
  tried and which address families the jail or host has.  A job's
  `no-repo-check` skips this (arcana-jobs pkg-upgrade, pkg-install and
  jail-base; arcana-packages refresh and upgrade; `arcanactl -R`; the
  package boxes' "Don't check the repository").  A pkg stopped for
  silence now says whether the repository answered when asked after.
- Watched pkg runs carry ARCANA_AGENT_JOB and ARCANA_AGENT_JOB_TITLE; at
  start the agent stops what a predecessor left of them (SIGTERM, then
  SIGKILL after 5 s) and lists each as a job that failed, "stopped: the
  agent restarted under it".
- arcana-bird gains a channel's family, preferred and filtered, and a
  BGP neighbour's interface; a link-local neighbour's address no longer
  carries `%iface`; routes counts are read when BIRD prints filtered, and
  a since of date and time is kept whole.  The BIRD tab shows the
  neighbour's interface and local AS, and each channel's family with
  its counts.
- Update the agents with the console: the jobs and packages actions
  gained a leaf, and arcana-bird four.

### IPsec policies by PF_KEY; agent 0.301.0, console 0.449.1

- **Policies** (PLAN-SDN-YANG 6.2.2): `ipsec-sa policy` sends a
  selector's traffic through an ipsec(4) interface's manual SAs as well,
  both ways (out at level unique on its reqid, in at level use), and
  `ipsec-sa unpolicy` takes them out; `clear` takes Arcana's policies
  after the SAs.  They are global PF_KEY policies of a priority of
  Arcana's own (0x7fa2c000), after ipsec.conf's; ipsec.conf's, an IKE
  daemon's and the interfaces' own are never touched (a selector of
  theirs fails the job), and policies are deleted by the id a dump
  read, never by selector.
- `ipsec-sa set` and `derive` now fail, before anything changes, when
  the reqid given is not the one the interface's own policies have.
- The ipsec.conf read shows the kernel's SPD read by PF_KEY, each policy
  told whose it is; the agent no longer runs setkey(8) at all
  (ipsec.conf itself is still rc.d/ipsec's).

### A host's terminal, agent 0.300.0, console 0.449.0

- A host's **Terminal** tab runs that host's own login(1) on a
  pseudo-terminal (arcana-stream's new terminal command), or a jail's
  own login through jexec(8), in xterm.js (5.5.0, with addon-fit
  0.10.0, vendored; MIT).  The person logs in with an account and
  password the host checks with PAM; Arcana picks no user and runs no
  shell of its own.  Only console users signed in with a security key
  who are operators or admins of the host may open one (no API tokens),
  and each session is in the audit trail (terminal-refused,
  terminal-opened, terminal-closed with bytes each way, its length,
  the login name when the host tells it, and why it ended).  The agent
  allows 8 sessions at once and hangs up one nobody types in for 30
  minutes (`--terminal-idle`); `--terminal-login` names the program for
  tests.  Hosts whose NACM exec-default is deny give terminals to group
  admin only until a rule permits `arcana-stream:terminal`.  Update the
  agents before using the tab: an older agent refuses the stream.  The
  plan is docs/PLAN-TERMINAL.md.

### SD-WAN's plan after a keep, console 0.448.3

- SD-WAN: the Edges tab no longer shows a loader for good when the plan
  answered before the document's reread after a form's keep; a plan
  asked before a keep is dropped and asked again.  Deploy, when
  refused, says why on the button and in its title (no plan, an apply
  runs, packages missing, nothing to do).

### RFC 9899's defined sets, agent 0.299.0, console 0.448.2

- RFC 9899's defined sets (ietf-acl-enh; PLAN-SDN-YANG 6.1.5) are
  served with the ACLs and compiled to ipfw: prefix sets (and aliases'
  prefixes) as tables named acl-0-*/acl-1-*, which the ACLs own like
  sets 28 and 29 (an admin's rule naming one refuses an ACL edit, as
  does net.inet.ip.fw.tables_sets=1); port sets as lists or number
  tables, protocol sets as or-blocks, ICMP type sets as lists, aliases
  decomposed.  An edit fills the other generation's tables and swaps
  sets 28 and 29; no table is ever swapped.  RFC 9899's fragment,
  extension-header, flags-bitmask, log-action, counter-action and
  rate-limit are refused until compiled.  The new module
  arcana-acl-deviations lets RFC 8519's IPv4 flags stand alone again
  (RFC 9899's ipv4-fragment must refused them).  SIDs 94 600 to 94 899.
  Update the agents together with the console.

### IPsec SAs by PF_KEY, agent 0.298.0

- Manually keyed IPsec SAs (`ipsec-sa` set, derive, commit, clear;
  PLAN-SDN-YANG 6.2.1) are set by PF_KEY (pfkey(4) messages, as
  setkey(8) builds them) from the agent's own process, and each SA is
  read back after it is added: the job fails and says what differs.
  setkey(8) is no longer run for them; the agent's `-9 setkey` option
  is gone and `--pfkey socket` points it at a test's stand-in.  A clear
  deletes each SA between the two ends by its SPI, found by a dump,
  rather than with setkey's deleteall.  Otherwise unchanged (the same
  window, ESN, NAT-T and algorithms); needs ipsec.ko loaded, as before.

### ACL refusals, logging and statistics; agent 0.297.0, console 0.448.1

- **ACLs** (PLAN-SDN-YANG 6.1.3, 6.1.4): what ipfw cannot match is
  refused with the node at fault as the error-path and the reason in
  the message (operation-not-supported; invalid-value, in-use and
  resource-denied for the rest); arcanactl says the node after a
  refusal at commit, "(at /module:...)".  log-syslog compiles to the
  rule's `log logdst syslog` (syslogd(8), LOG_SECURITY, capped by
  net.inet.ip.fw.verbose_limit).  Feature acl-aggregate-stats: each
  ACE's statistics in the operational datastore are its rules'
  counters, counted from the last edit.  The console rebuilds for the
  feature.
- **libcblink 0.2.29**: the node a handler names is kept as the
  error-path at commit (it was replaced by the handler's top node, so
  every handler's error-path was lost).

### The archive's settings on the page, console 0.448.0

- A host's Monitoring tab has an Archive form under Sampling
  (PLAN-SDN-YANG 5.6.3): whether the agent archives its samples, the
  budget in MiB, and each class's step (10 to 3600 s, 60 when empty)
  and retention (1 to 3660 days, 30 for host and 7 for the others when
  empty), checked as the agent checks them and saved with the sampling
  in one commit of arcana-history, so neither form loses the other's
  settings.  Kept in history.conf as `archive=`, `budget=` and
  `class=name:step:retention`; before, only RESTCONF or the file set
  them.

### BIRD's Configuration button, console 0.447.1

- The BIRD tab's Configuration button stays disabled until the host's
  configuration has been read (its title says so); before, a click
  while it was still loading did nothing.

### SEN of the daemons' blocks, SAN on every path; agent 0.296.0, console 0.447.0

- **SEN for blocks by unbound, Squid and c-icap** (MEF 138, SASE-6):
  the agent reads the SD-WAN daemons' own logs of what they blocked
  (DNF and PDNS by unbound, URLF, MBSF and DNF's inner wildcards by
  Squid, MD+R and malware by c-icap and ClamAV), matches each line back
  to its zone, function policy and list, and tells it as the new event
  sdwan-block (arcana-events' block case, SIDs 80162 and up); the
  console makes a SEN of it as of ipfw's denies and Suricata's alerts.
  Update the console with the agents.  The services' Squid now logs in
  its own arcana format to `-v`'s directory (`/var/log` by default)
  `/squid/sdwan-sw<fib>-access.log`, c-icap to
  `/c-icap/sdwan-sw<fib>-server.log`, and their unbound to
  `sdwan-dns-<name>.log` beside the agent's kept files, not to syslog;
  the next apply renders these files again.  A PDNS's A and AAAA
  entries and its no-match make no SEN yet (unbound logs none).
- **SAN on every path**: SANs are made where the L3NM is kept, so a
  RESTCONF write of it and the SAP network's merge make them too, not
  the document's PUT alone.

### ACL match table, agent 0.295.0

- **ACL match table** (RFC 8519, PLAN-SDN-YANG 6.1.2): the agent now
  compiles DSCP, length, IPv4's TTL, ECN not-ECT/CE, flags and
  identification, IPv6's flow label, TCP's sequence/acknowledgement
  numbers, flags (not CWR/ECE) and window, the ingress and egress
  interface, and Ethernet MAC addresses, masks and the IPv4/IPv6
  ethertype; the eth and mixed ACL types and features are served.  An
  ACL with an Ethernet match tags frames on ipfw's layer-2 pass and
  decides on the IP pass: it needs `net.link.ether.ipfw=1`, set by the
  admin (the agent never sets it), and is refused on an egress
  attachment.  Matches ipfw cannot express are still refused by name,
  nothing loaded.  No new SIDs.

### The long run on the page, console 0.446.0

- A host's Monitoring tab shows its long run from the agent's archive
  (PLAN-SDN-YANG 5.6.3b): pick a class (host, interfaces, disks, jails,
  FEC relays, probes) and a range (1 h, 6 h, 1 d, 7 d or all the class
  keeps); a class of many series is a table to pick one from; a gap is
  drawn as a gap; what the agent keeps per class is a table too.
  Setting the sampling on that tab no longer resets the archive's
  settings to their defaults.  Needs an agent with read-archive
  (0.294.0).

### Streams closed offline, console 0.445.1

- The page closes its fleet event stream and subscriptions while the
  browser is offline, and opens them again (reading what came in
  meanwhile) when it is back: before, they stayed open, and each event
  redrew the map under a drag on a large fleet.  And while the hand
  drags a host, bends a line or pans the map, the page draws nothing
  else until it lets go (or holds still 3 s): a tick, a late answer or
  an event no longer rebuilds the map under it, which on a large fleet
  also stalled the drag.  Found by the flaky pwa_test:pwa_map_fleet,
  which now runs in a few minutes and says what it saw when it fails.

### The archive, ACLs, rtadvd; agent 0.294.0, console 0.445.0

- **The archive** (PLAN-SDN-YANG 5.6.3): the agent keeps the long run
  of its samples on disk, in `archive/` beside history.conf
  (`/usr/local/etc/arcana/archive`; `--archive` moves it): the host's
  figures, each interface's, disk's, jail's and FEC relay's, and each
  probe target's, a point every 60 s per class, a file per class per
  UTC day.  The host is kept 30 days and the others 7, the whole
  within 128 MiB, the oldest day of any class going first.  Settings in
  history.conf (`archive=`, `budget=`, `class=name:step:retention`)
  and in arcana-history's new `archive` container; read with
  arcana-history's `read-archive` action (`arcanactl action history
  read-archive class=host`), also over the console's RESTCONF, which a
  viewer may use.  The history state gains `archive`.  Expect up to
  about 50 MB a week on a host with many probe targets.  The page's
  long-run view is not made yet.
- **Access control lists** (RFC 8519, PLAN-SDN-YANG 6.1.1): the agent
  serves ietf-access-control-list and compiles it to ipfw: set 29,
  staged in set 28 and swapped in whole, rule 8 and rules 60000 to
  64999.  An ACL change is refused while an admin rule sits at those
  numbers or in those sets.  The ACLs are kept in acls.cbor beside the
  agent's files and applied again at its start; nothing changes on a
  host until ACLs are configured.  New SIDs: 93 400 to 93 599.  The
  console's schema carries the module; nothing in the page reads it
  yet.
- **Router advertisements by commit**: `rtadvd_interfaces` is read as
  rc.d/rtadvd reads it.  With rtadvd enabled and the list unset or
  `auto`, a record's change leaves rc.conf alone and reloads rtadvd; it
  no longer stops rtadvd or narrows the list to one interface.  A
  change auto cannot express is refused: name the interfaces in
  `rtadvd_interfaces` first.  Taking the last interface off sets
  `rtadvd_enable=NO`.  A host already left with `rtadvd_enable="YES"`
  and an empty `rtadvd_interfaces` in /usr/local/etc/rc.conf.d/arcana
  runs rtadvd on every IPv6 interface at its next boot: set
  `rtadvd_enable="NO"` there.
- **BGP routes on the page**: the SD-WAN Paths tab now shows each
  service's BGP routes (BMP) from the agents' reads, which the page's
  own read had left out, so the view showed nothing before; its tables
  have a filter, cleared when SD-WAN opens or the tab changes; a host's
  edge no longer shows its vnet jails' BIRD instances.
- **BMP of a vnet jail's edge**: a station's listener, made in the
  jail, is closed when the jail stops (it held the jail dying) and made
  again in the jail's new network when it runs again, so the station
  hears BIRD after a jail restart without the service applied again.
- **libcblink 0.2.28**: a list's keys, `unique` statements and a
  leaf-list's values are checked in linear time (they were quadratic
  in a peer's edit); an optional connection limit per source address
  (`CBL_LIM_MAX_CONNS_PER_SRC`, off unless set); a union's string
  member chosen by the validator's own patterns, in C.UTF-8; a mounted
  node keyed twice refused.

### Route monitoring, agent 0.293.0, console 0.444.0

- **BMP** (RFC 7854, PLAN-SDN-YANG 5.6.2): a service's **Route
  monitoring** (the service form's last fieldset; arcana-l3nm's
  route-monitoring, updates-kept 64 unless set) has each of its BIRD
  instances send BMP to the edge's agent, on 127.0.0.1 port 1790 plus
  the instance's FIB (arcana-agent's new `--bmp-port` moves the base).
  The agent keeps each BGP peer, up or down, its prefixes announced and
  withdrawn before and after the import policy, and the last updates;
  the console reads them with the edge's state (arcana-sdwan's bmp
  under each BIRD instance) and the service's page shows them under
  **BGP routes**.  A monitoring instance's BGP channels keep their
  import table, which BIRD needs for the pre-policy view: more memory,
  a full table's worth for a full table.
- arcana-sdwan has a third SID range (93 200); arcana-l3nm two new
  items.

### libcblink 0.2.27, agent 0.292.2, console 0.443.2

- **libcblink 0.2.27**: once `cbl_conn_free()` returns on a thread other
  than the connection's loop, nothing more is delivered on it (before,
  the loop could still answer a request already arriving before the
  posted teardown ran).  Found by the VM round.
- Agent root tests: `routes` opens a socket of its own (a host with no
  listener had none to list), `probe_dscp_packets` reads tcpdump's IPv6
  lines that leave out a class of 0, `jail_make` expects the refusal of
  a file with another jail's block.

### Alternate marking off, agent 0.292.1, console 0.443.1

- **Alternate marking is refused** (the service form's block, the
  rules' `altmark`): it swaps two ipfw tables of `valtype dscp` each
  block (`IP_FW_TABLE_XSWAP`), and the kernel's ipfw corrupts their
  values when it does (three swaps leave `62 61` where `62 63` was) and
  panics when they are flushed (`Refcount is 0 on kidx`, in
  unref_table_value; on a kernel with INVARIANTS).  Found in the VM
  round with plain ipfw commands.  The code stays, refused at the
  console's check and at the agent, until ipfw is fixed.

### Flow records, agent 0.292.0, console 0.443.0

- **A service may record its flows** (NetFlow version 9, RFC 3954;
  PLAN-SDN-YANG 5.6.1): the service form's **Flow records** (an IPv4
  collector, its UDP port, 2055 by default; one packet recorded in N;
  the active and inactive timeouts, 1800 and 15 s), arcana-l3nm's
  `flow-export`.  Each edge then has, for each such service, an
  ng_netflow(4) node `arcnfK` given a copy of each packet into and out
  of the service's tunnels by ipfw `ngtee` through ng_ipfw(4) (rule 9
  of the SD-WAN set, hooks 61000 and up), its records sent by an
  ng_ksocket(4) over UDP from FIB 0.  The console has each such edge
  load and keep ng_ipfw, ng_netflow and ng_ksocket; the agent refuses
  the records where ng_ipfw is not loaded, since an `ngtee` rule then
  drops what it matches.  The nodes go and come with the set.
- **Host edges alone**: ng_ipfw's netgraph node is the host network's,
  so an edge that is a vnet jail (or an agent itself in one) cannot
  record flows; the console leaves such edges out and the agent
  refuses flowexp there.
- ng_netflow sends a datagram once it is full: a quiet service's
  expired flows wait until more come (a flush is kernel work, TODO.md).
- An agent before 0.292.0 refuses the rules' `flowexp`: update the
  agents before turning it on.  arcana-sdwan and arcana-l3nm are
  numbered again.

### A commit's warning always said, console 0.442.3

- What the host warns of in a commit it took (a condition it had
  before, a reference to an interface not there yet) is a toast of its
  own after any save of the page's (ycommit.c); before, a form that
  closed on success and toasted its own words (the generic YANG form,
  the job lanes, router advertisements, a tunnel's monitors, sampling)
  dropped it.

### Every alarm type a row of the alerts' cases, console 0.442.2

- Settings, Notifications: the mail's and Telegram's cases have a row
  for each type a host's alarm inventory (`ietf-alarms:alarms/
  alarm-inventory`, RFC 8632) has that the page does not name, labelled
  with the host's description; before, a newer agent's type had no row
  until a case was kept for it (the agent's `alarm-list-full` had none).

### A job's program followed while it runs, agent 0.291.0, console 0.442.0

- **Follow output**: a job's program step, picked in its trace while it
  runs, has **Follow output**: what the program has written so far,
  standard output and standard error, at once, then each piece as it
  comes, until it exits ("The program has exited"); **Stop** lets it
  go.  One step at a time on a page.
- On the agent, arcana-stream's command 5, `exec-follow` (names `job=`
  and `step=`, the step's number in the job's trace): a job's program
  keeps a live copy of its output while it runs (ira/live.c) and sends
  it to each follower, sixteen at once at most; the copy is let go once
  the program has exited and no one follows, the output being in the
  trace from then on.  A program whose output is not kept (keys in its
  words) has none to follow.  Every role that reads a job's trace may
  follow it (NACM's default; no rule needed).
- On the console, a page's stream takes the source
  `out-<host>.<job>.<step>`, judged as a read of the host is: each piece
  an event of that name, `{"text": ...}`, whole UTF-8 characters; the
  end `<name>.end` with `{"done": true}`.  Taken again it starts from
  the program's start.
- `arcanactl job-follow id step` writes the same to its standard
  output.
- A service job that ended no longer reads the settings of a service
  with no name (no service open) and takes the trace with that read's
  error.
- A program's output comes as the program writes it: one that holds its
  output back while it writes to a pipe (stdio's buffer) comes in
  pieces of that buffer.

### Alternate marking, agent 0.290.0, console 0.441.0

- **A service may measure its tunnels by alternate marking** (RFC 9341):
  the service form's **Alternate marking block, s** (arcana-l3nm's probe
  `alt-marking-period`, 2 to 3600 s; none, off).  The edges' ipfw then
  has, in the SD-WAN set (30): on the way out of each tunnel, first of
  all (rule 9), two `count` rules and a `setdscp` that clears the
  colour bit; on the way in, last (rule 11, after the console's rules
  there that only count or mark, before its first that ends the pass:
  a flow's dummynet queue or pipe, the skip to the way out), a
  `setdscp tablearg` that sets the DSCP's lowest bit in every other
  block, two `count` rules, and a `setdscp` that clears the bit on the
  outer header of the tunnel's own packets alone (GRE; IP in IP or IPv6
  for gif; UDP to the far end's port for wg and GENEVE; ESP too when
  IPsec carries it; a uswe or relayed tunnel's outer packets keep the
  colour on the underlay); two colour tables a service and
  `arcam_even`, made and destroyed with the set.  A flow's queue or pipe
  by DSCP matches the class and its coloured neighbour (`dscp 46,47`):
  nothing follows dummynet (`net.inet.ip.fw.one_pass`), so the colour
  comes before it, and its count of what went into the tunnel counts
  what dummynet then drops (a full queue, a pipe's rate) as lost in the
  tunnel.  The admin's own rules are not touched: the marking goes and
  comes with the SD-WAN set, its kept file, its undo and safe mode.
- **DSCPs**: the standard classes (CS, AF, EF, VA) keep their codepoints
  on the underlay and past the far end; inside a tunnel an odd block's
  packets carry the class's DSCP plus one.  What came with the lowest bit
  set (LE, RFC 8622's 1; the local and experimental pools) is carried as
  its even neighbour (LE as CS0).  A service with alternate marking takes
  only even DSCPs for its probes and classes (refused otherwise).  What
  remains so while a service has alternate marking on: an admin's own
  rule after Arcana's band (past rule 99) that matches a DSCP on the way
  out by a tunnel sees the colour in odd blocks (`dscp 46` misses half
  the EF; write `dscp 46,47`), and one that sets a DSCP there overrides
  the colour (those blocks show everything lost one way); traffic that
  arrives with the low bit set (LE, the local-use codepoints) is
  delivered as its even neighbour.
- **Blocks are the wall clock's**: both ends of a tunnel number them by
  CLOCK_REALTIME over the block's length, so the edges' clocks are kept
  within a quarter of a block of each other (ntpd, chronyd); a block read
  outside its guard band is marked not valid.
- The loss of each tunnel's each way by block and RFC 9342's clusters
  are the Paths tab's **Alternate marking** tables and
  `/restconf/data/arcana-console:sdwan/alt-marking`; each edge's blocks
  are arcana-sdwan's state (`alt-marking`) and the event `sdwan-altmark`.
  An agent before 0.290.0 refuses the rules' `alt-marking`: update the
  agents before turning it on.  arcana-sdwan, arcana-events, arcana-l3nm
  and arcana-console are numbered again.

### A cluster's setup and enrolment tokens through its log, console 0.440.0

- **A cluster's setup token is its leader's.**  The node that leads
  makes it, writes its text to its own `setup-token` alone, and puts its
  SHA-256 through the log; every node takes it, and its sign-in page
  says which node has it (`setup_node` in `/api/auth/status`).  A
  follower that had a `setup-token` of its own takes it away.  Before
  there is a leader a node says so (503, `setup_waiting`) instead of
  making one.  The first owner, by a key or by a password, is the write
  of the log that spends the token: one registered on another node at
  the same time is refused, "set up already".
- **Enrolment tokens are the cluster's**: made on one node, a host
  enrols with it through any node, once; one sent to two nodes at once
  enrols once.  A token lasts `enrol_ttl` seconds (web.conf, 3600 by
  default) by the leader's clock.  An enrolment token made before the
  update was in one node's memory and is gone: make another.
- **Every node of a cluster is updated before a token is made**: an
  older node passes over the new writes of the log, and would not know
  the tokens.  A cluster set up before keeps its owners; one not yet set
  up is set up with the token its leader makes once all are updated
  (`cluster-tokens.json` in each node's data directory is the cluster's
  and is written by the log alone).  Without `WITH_CLUSTER` nothing
  changes.

### libcblink 0.2.24: rules held whole, the configuration held whole, agent 0.289.0, console 0.439.0

- **Access rules with a path that does not compile** (a prefix such as
  `/if:interfaces` where the module's name goes, a typo) are no longer
  passed over.  A deny rule of them denies, to its rule-list's groups and
  for its operations, all of the module its `module-name` names (or its
  path's first step, where that is a module; else every module); a
  permit rule never matches.  The agent raises the fault `nacm-rules`
  (Major for a deny, Minor for a permit) on `nacm` with the rule and why,
  and clears it once the rules are written whole.  Writing such a rule
  is refused; the access rules form says why.
- **A path rule with key predicates** is held to an action's target
  (`$USER` too), and a delete is checked for every node it takes away.
- **A commit holds the whole configuration** to its `when`s, `must`s and
  references: a change that leaves another node's leafref dangling is
  refused.  What a host had failing before, left as it was by the
  change, is not: the commit's answer warns of it, and the page says the
  warning with the save.  A reference to what is not there (a route by
  an interface a service, a clone or a jail makes later) never refuses a
  commit on a host: running is the live system's, and the commit warns
  of it, naming the leaf.
- **JSON to a host** is stricter: a member name that is a path, one
  child named twice (`x` and `m:x`), a decimal64 number with more
  fraction digits than its type has, are refused rather than taken
  otherwise.

### The page's streams on one EventSource, console 0.438.0

- **Each page holds one event stream**, `GET
  /restconf/streams/page/json?fleet=1&sub=<id>,<id>`, instead of one for
  the fleet's stream and one for each subscription: every tab shares the
  browser's one HTTP/2 connection, and the streams held on it are few.
  Each event is named by its source, `fleet` or `sub-<id>` (and
  `<name>.open`, `.end`, `.error`, `.info`); a subscription established
  later, or given up, is said to the stream by `POST
  /restconf/streams/page/<stream id>` from the same session.
- **A plugin that listened to `window.arcanaStreams[<id>]`** (an
  EventSource each) listens on `window.arcanaStream` for the source's
  name instead; `window.arcanaStreams` now maps the page's ids to those
  names.
- `/restconf/streams/<host>/json`, `/restconf/streams/fleet/json` and
  `/restconf/subscriptions/<id>` stay as they were, for RESTCONF clients.

### Console plugins: themes and guide packs as data, code only when trusted, console 0.437.0

- **A plugin with scripts or styles must say `"trusted": true`** in its
  `plugin.json`, or the console lists it as refused, with why, and
  serves none of it: its scripts run as every user who opens the page,
  with their session.  An enabled plugin that does not say so stops
  being served at the console's first look after the update (open pages
  keep its code until they are loaded again).  Settings, Plugins shows
  trusted plugins apart, under a warning, and asks the owner before
  enabling one; an owner who enabled one before has it enabled still,
  once its manifest says it is trusted.
- **Themes and guide packs are data**: the manifest names them
  (`themes: [{id, name, file}]`, `guide-packs: [{id, name, expressions,
  lines}]`), the console checks their JSON (a theme's tokens by name and
  grammar, no `url()` or anything that fetches; a pack's pictures files
  the plugin lists; every string text) and the page applies them with
  its own code, with no script of the plugin's.  `provides` says
  `theme` and `guide-pack` exactly when the manifest has them, and a
  plugin of data alone provides nothing else.  `plugin.json` is now
  served too (the page reads it).  A data plugin disabled is put away
  at once, in open pages too.
- **What an admin does**: a script plugin that only provided a theme or
  a guide pack loads again only once marked `"trusted": true`; better,
  rewrite it as data (its manifest names its files, its script goes).
  The first-party ones are converted: `template` 0.2.0 and
  `guide-after-hours` 1.1.0 are data, `game-mode` 0.31.0 is trusted and
  takes the guide packs of data (`Arcana.on("guide-packs")`); each needs
  this console.  Install the new copies over the old directories.
- An SVG of a plugin is served with a policy of its own (`sandbox`,
  nothing fetched) and as an attachment: a picture for an `<img>`.
- A theme picked from a plugin is kept in the browser as
  `p:<plugin>/<id>`; when its plugin is disabled the page wears the
  default until it is enabled again.

### The cluster chosen at the build, and Raft made safer, console 0.436.0

- **A console has no cluster unless it is built with one.**  From this
  version a console built from a tree or from the port is built
  without the cluster (`nodes.c`, its Raft, the consoles' family):
  `WITH_CLUSTER=yes` in `config.mk` (`make config` offers it) or the
  port's `CLUSTER` option (off by default, `make config` in the port)
  builds it.  A console that stands alone needs nothing: its data
  loads as before, and nothing of the cluster listens.  **A deployed
  cluster must choose it before updating**: a node built without it
  refuses to start with its `cluster` block, saying "built without the
  cluster: build with WITH_CLUSTER=yes".  For **Update console** the
  line goes in `/usr/local/etc/arcana/config.mk` of the host the
  console runs on.
- **A cluster's nodes are updated together.**  The consoles' family
  changed (a pre-vote, when an append was sent, a lock's write and its
  token) and so did a lock's write in the log (how long, not until
  when): stop every node, update every node, start them again.  The
  data directories, `cluster/` among them, stay as they are.
- **Raft.**  A node that heard from the leader within the least
  election time (1.5 s) votes for no other, and a node asks whether
  it would be elected before it raises its term (the pre-vote): one
  cut off from the leader alone, or from all, no longer unseats it.  A
  leader's lease is reckoned from what a majority answered in its
  term, never whole at its election, so two nodes never both run the
  schedulers or grant a lock.  The term, the vote and the log are
  written by a thread of their own, the votes and acknowledgements
  sent once they are kept, the directory fsync'ed with each rename.
  The documents a node is sent never take it back past what it
  applied, and it keeps the writes after them it holds.
- **Locks** are held once their own write is applied as it was
  given (a leader that loses its place first gave nothing), and each
  node keeps a lock's time by its own clock.  An **SD-WAN apply** is
  one in the cluster at a time: another node's apply is refused with
  409 while one runs, and an apply whose lock is lost (renewed before
  each step's jobs) stops rather than go on beside another.
- **A change a follower made, not yet written on it in five seconds**,
  is accepted all the same (it is the cluster's); until the follower
  has written it, every reply of that node carries `Warning: 110` and
  its `arcana-console:cluster` says `behind`.
- **The audit trail and the SENs and SANs are each node's own** in a
  cluster: each record says the `node` that kept it (a console of no
  cluster writes them as before).

### Feeds held back, viewers' reads, the hosts' default for actions, console 0.435.0, agent 0.287.0

- **Threat feeds.**  The agent loads a feed's table by libipfeeds' own
  sh(1) script, under the same lock as `ipfeeds(8)`
  (`/var/run/ipfeeds.<table>.lock`, lockf(1)): a cron job of
  ipfeeds(8) on the same table waits for the agent's load and the
  agent for it.  The console no longer delivers a list of fewer than
  half the entries of the one delivered last: the feed says *held
  back* with both counts, the hosts keep the last list, and a console
  owner, or whoever last saved the feed, presses **Take it anyway**
  (arcana-console's `threat-feeds/feed=<id>/take`).
- **Viewers and the hosts' programs.**  A viewer's service read, and
  the services list's running state, come from what the agent last saw
  (an operator's or the admin's read, or the agent's own look every
  five minutes): no rc.d script runs for a viewer, and the detail has
  no description for one.  A vnet jail's own ipfw, swanctl, ifmcstat,
  birdc, wg and sysctl are run for an operator of the host alone.
  Viewers who read those in jails now see why they are refused; give
  them an operator's role on the host where they need them.
- **The hosts' default for actions** (Settings, AAA, Roles): permit, as
  before, or deny, written by the next **Synchronize roles to the
  hosts**: exec-default deny, and every action Arcana lets every role
  run permitted by name for every user.  Nothing changes on a host
  until its roles are synchronized; reads stay permit.
- **stampd's keys.**  A tunnel whose derived SSID already has four
  keys in the key file (the admin's counted) has none written: logged,
  and a Warning fault `stamp-unauthenticated` on `reflector:<target>`.
  A key file stampd would refuse (an admin's fifth key of an SSID) is
  not written, nor stampd told: a fault on `reflector:<key file>` until
  it is mended.
- **HAST.**  `hastctl create` and a role are refused for a resource
  whose local provider is the system's (mounted, swapped on, a pool's).
- **Faults** of SD-WAN BIRD instances, their neighbours and BFD
  sessions, IDS instances, the mail watch and manual IPsec key
  rotation that an agent before left open for a subject since gone
  are cleared at the new agent's first look.

### Tokens as themselves, sign-in, enrolment, console 0.434.0, agent 0.286.0

- **API tokens on the hosts.**  A read token is said to a host as the
  NACM user `token-read` (in no group: a viewer, secrets masked, BIRD's
  texts and the services' values left out), a write token as its
  maker, no longer as `console`.  A write token whose maker the host's
  rules have in no group (an owner made after the host's roles were
  last synchronized) is refused there what the maker would be: an
  owner synchronizes the roles once (Settings, AAA, Roles, or each
  host's nacm-sync) and it is let.  A token reaches no more of the
  console than its maker's console role and tenant allow either: the
  token of a tenant's user no longer reads the SD-WAN, the L3NM, the
  virtual networks, the prefix lists or the threat feeds.  `console`
  and `token-read` are no user's names.
- **Signing in.**  The sign-in start names no key.  A passkey (a key
  registered as a discoverable credential, as the console has asked
  since keys were first registered, when the authenticator could)
  signs in with **Sign in with a key** and no name.  A security key that
  keeps no passkey is asked for by its user's name: the browser that
  signed in before remembers it and the button works as it did; on
  another browser, **An older key? Sign in by name** with the user's name
  (`admin` for the built-in owner).  The owner who signed in only with a
  key sees no change on the same browser.
- **One's own password** is changed with the current one, or, for one
  with none yet, with one's key (the browser asks for it); an owner
  sets another's as before.
- **Enrolment tokens** (`arce1_...`) carry the CA's fingerprints: the
  console's command is `arcana-enrol -s <url> <token>` alone, and the new
  `arcana-enrol` needs such a token (or `-f`, or `-i`).  Tokens made
  before the update no longer work: make another.
- **The unix listener** is 0660, owned by the console's user, its group
  the console's own unless `listen_group` names another (a reverse proxy
  that connects over it must be in it, or named); `listen_mode` sets
  another mode.

### Links in the files the agent writes, agent 0.281.0

A file the agent changes through libvarconf (rc.conf and its
rc.conf.d files, sysctl.conf, loader.conf, rtadvd.conf) that is a
symbolic link stays one when root made it: the file it names is
written, beside itself, where before the link was replaced by a plain
file. Anyone else's link is refused, neither followed nor replaced.
The directory written in must be root's and writable by no one else
(not group, not other, sticky or not), else the write is refused with
why. One of several hard links is refused: make it one file, or the
others symbolic links. A string written
into rtadvd.conf holds no control character, and after a ":" (where
rtadvd splits a field) addresses' hex digits, dots, "/" and ","
alone, never another field. The agent and the console are built with
`_FORTIFY_SOURCE=2` and full RELRO.

### The build user, reads by role, signed versions, agent 0.284.0

Update the console first, to 0.433.0 or later, then the agents: from
agent 0.284.0 on, an update's signature covers the host it is for (its
hostname), its version, its SHA-256 and whether it may replace a newer
agent (downgrade), and an agent refuses a program a console before
signed. The console of 0.433.0 signs the new way.

An agent builds (**Build agent here**, **Update console**, `arcanactl
agent-build`) as `_arcanabuild`, a user of its own, no longer as
`nobody`, whose processes are every daemon's; what it builds is signed
by the console and run as root on every host. The agent makes no user:
the package makes it (UID and GID 863); on a host whose arcana was
installed before 0.284.0, or by `make install` from a tree, make it
once, as root:

```
pw groupadd _arcanabuild -g 863
pw useradd _arcanabuild -u 863 -g _arcanabuild -c "Arcana agent builds" \
    -d /nonexistent -s /usr/sbin/nologin
```

A build is refused until it exists, with that line. It is refused as
well as `nobody` or root, as a user with a process of its own running,
or with a home of its own (`--build-user` names another). The build
directory, `/var/cache/arcana-build`, becomes `_arcanabuild`'s, mode
0700, at the next build; the deploy key in it stays as it was (its
public half needs no change on the repository's server). A key of your
own for git (`agent_ssh_key`) must be readable by `_arcanabuild`.

The reads every role has give a viewer less: a log that is not
world-readable on the host (auth.log, security, cron's) and the audit
trail are an operator's; BIRD's configuration texts and services'
variable values are left out of a viewer's GET (`nacm:default-deny-all`;
an operator's too, unless the host's rules permit them); a process's
argv, jail.conf's text, sshd's key options, smtpd.conf and its tables,
a relay's log, a storage keylocation, a rule source's url and a
poudriere make.conf have their secrets masked (`<hidden>`) below an
operator, and a job's steps for everyone; a core's backtrace is an
operator's; ipsec.conf's keys are masked below an admin. Nothing is to
be done by hand.

### Modes, secrets and guards, agent 0.283.0

Agent 0.283.0 runs with umask 077, the programs it runs with 022 as
before. At its start the SD-WAN's kept and rendered files beside its
own (`sdwan-*` in `/usr/local/etc/arcana`) an agent before left 0644
become 0600 (a proxy's that Squid reads, of group squid, 0640), and
the directory 0711. A jail's rc.conf is read and written by `sysrc -j`
and the jail's number, no longer `-R` and its root. ctl.conf's CHAP
secrets are read as `"********"`, and a write that gives the marker
back keeps the file's; a job's title and trace hide the value of a
variable whose name says it is a secret, and a bundle exported without
secrets withholds a file that holds one. A dataset or provider of the
system's (a pool's root, its boot environments and bootfs, what is
mounted where the system lives, mountpoint none or legacy, swap, a
pool's devices) is refused for destroy, rollback, a jail's removal and
GEOM's wiping verbs, with why. Nothing is to be done by hand.

### Faults held to what is watched, agent 0.280.0

At its first start, agent 0.280.0 clears the open faults an agent
before it left of what it no longer watches: a probe's target or link
gone, a threshold taken away, a file system gone, a session BIRD no
longer has; each with its line ("...: no longer measured"). Those of
what it still watches stay open, and are cleared when their cause is,
as ones it raised itself. A kept `alarm-control.json` whose shelves
are not the model's arrays (a hand's edit) is refused with why, and
the agent starts with no shelves; set them again. A samples file whose
head is cut short is put aside as `.bad`, and sampling starts anew.

### The console's role, agent 0.279.0

From agent 0.279.0 on, a peer over TLS is the console only when its
certificate says `URI:urn:arcana:role:console` in its subjectAltName;
one that says neither role, as a certificate from before the roles
does (hosts' among them, valid 825 days), asks nothing and is refused.
Update the console first, to 0.427.0 or later, then the agents:

1. The console, at its start, reads its own client certificate. Where
   it holds its CA's key (its own CA, or `tls.ca_key`), one without the
   role is signed again for the same key, which stays where it is, the
   one before kept beside it as `.before-roles`; the log says so. Each
   node of a cluster has its own data directory and certificate, and
   does the same for its own. Without the CA's key it logs what to do,
   at each start: sign the certificate again by the CA with
   `URI:urn:arcana:role:console` in its subjectAltName and `clientAuth`,
   put it in place of `tls.cert` and restart the console.
2. Then the agents, from the console (**Update N agents**): the console
   reaches them with the new certificate, which the agents before took
   as well.

An agent updated first refuses a console whose certificate has not the
role yet, until the console is updated (or its certificate signed
again by hand) and restarted.

### The switch to YANG alone

Console 0.336.0 and agent 0.238.0 speak only cblink's YANG family
(and the agent's own stream families): the interim protocol, the
`arcana` family of `arcana.yaml`, is gone, and no release keeps it. A
console of the switch reaches an agent before it (0.236.0, 0.237.x)
for two things alone: its `hello` (a read of arcana-host's host, which
those serve, with their version and build) and the update
(arcana-agent's `update` action, which they serve: the program as it
is, signed, within its frame). Everything else such an agent serves
through the interim protocol alone fails against it until it is
updated. So, on the flag day:

1. Update the console first (**Update console** on its own host, or
   `pkg upgrade arcana`, or the container image). The agent of the
   console's host is updated with it.
2. Then every other agent, from the console's **Devices** page:
   **Update N agents**, with **Restart the agent now** on. The console
   sends each the agent installed with it, as it is; each answers as
   the new build once it has restarted, and from then on takes its
   updates compressed.

In between, a host whose agent is still of before shows only its hello
(its version and build) and offers the update, and every other page of it (jails,
services, networks, the firewall, SD-WAN, jobs) fails until that host
is updated. `arcanactl` of the switch is the same: `hello` and
`agent-update` reach an agent of before, nothing else. A host the console
cannot send the agent to (another architecture, another FreeBSD
version) is updated with `pkg upgrade arcana` on the host.

With **Restart the agent now**, on by default, the host then restarts
its `arcana_agent` service. The console watches for it to answer as the
new build and says when it does; if it has not after 45 seconds, it
says the service did not restart, which is what happens when
`arcana_agent_enable` is not set or the agent was started by hand (the
host's log says which); without it, the new program runs from the next
start of the service. A restart drops jobs still queued on the host; one that is
running finishes first. From a shell, `arcanactl agent-update [-r]
program` does the same for one host, compressed when the agent takes it
so; `-p` sends it as it is.

The program has to suit the host: the same architecture, a FreeBSD
version it runs on, and `devel/libcbor` installed (libcblink is linked
into the agent). Hosts that differ
from the console's machine are updated with `pkg upgrade arcana`
instead, which the Packages tab can do. If an update goes wrong, put
`arcana-agent.old` back and restart the service.

## Building the agent on a host

The console need not have the agent it sends: it can have a host build
it. Name the repository in `web.conf`,

```
agent_source = "https://github.com/arcana-org/arcana.git";
agent_ref = "main";            # a branch or tag; optional
```

and each host's header gets **Build agent here**. That host clones the
repository afresh into `/var/cache/arcana-build`, builds cblink, the
libraries and `arcana-agent` with `make`, and sends the program back, compressed
when it can (as above); nothing is installed there. The console inflates
it, checks it against its SHA-256, keeps it in
`agent/` under its data directory, and sends that one from then on, so
the hosts that run another build are offered the update. The build is
in the activity bar with the output of git and make.

When git fails, the entry in the activity bar says everything git said
(its last line alone is only the end of its advice), and **Raw output**
has it verbatim.

A repository reached over SSH (`git@host:path`, `ssh://…`) takes two
more things, since git runs there as a user with no known hosts and no
key:

- **The server's host key.** The host that builds never takes it on
  trust. The first build stops and the console shows the fingerprints
  of the keys the server presented; compare one with what the server's
  administrator gives, and confirm. The host keeps the confirmed keys
  in `known_hosts` in its build directory and checks the server against
  them from then on. If the server later shows another key, the build
  fails and says so in capitals, and the dialog asks again.
- **A key for the host.** By default the host makes one for itself
  (`id_ed25519` in the build directory) and the dialog shows its public
  half: add it to the repository's server as a read-only deploy key.
  To use a key of your own instead, put its path on the build host in
  **Settings**, "SSH key for git" (`agent_ssh_key`); it has to be
  readable by `_arcanabuild`, whom git runs as.

From a shell, `arcanactl agent-build -y` confirms the keys shown, and
`-i key` names the key.

The host that builds needs what the build needs: `git`, the base
compiler, `devel/libcbor` and `net/libyang3` (for cblink-gen, which
reads the wire's YANG modules); cblink is cloned with the tree, a
submodule, and built with it. If the linker or a library is somewhere
else on it, `/usr/local/etc/arcana/config.mk` there is copied into the
tree as its `config.mk`. When the agent is root, git, make and
ssh-keygen run as `_arcanabuild`, a user nothing else is (below). From
a shell, `arcanactl agent-build [-o file] repository [ref]` builds and
saves the program.

## Versions

The agent and the console have versions of their own, and every change
to one bumps it: `ARCANA_AGENT_VERSION` in
`usr.sbin/arcana-agent/agent.h`, `ARCW_VERSION` in
`www/arcana-console/console.h`. A host's header and the tree show the
agent's; the update dialog shows the one the console would send.
