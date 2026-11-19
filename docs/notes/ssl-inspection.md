# SSL inspection: the phases

How [inspection.md](inspection.md)'s plan is built, a phase at a time.
Decided 2026-10-23: SSLproxy (security/sslproxy) opens TLS
transparently, the clients' traffic sent to it by an ipfw(8) `fwd`
rule; a root CA per tenant fleet, made and kept by the console, an
intermediate per edge whose key is made on the edge; SD-WAN's
transparent TLS moves off Squid's ssl-bump; SSH is seen and logged,
never opened. Arcana installs nothing by itself: the plugin's Install
button is the admin's to press.

## Phase 1: the plugin, its CA, its rules (built)

- **Detected**: `sslproxy` is a plugin of the hello's list
  (`/usr/local/bin/sslproxy`); the Security page's SSL inspection tab
  offers `pkg install sslproxy` while it is not there.
- **The service**: the port has no rc script, so Arcana ships one,
  `arcana_sslproxy` (share/rc.d), as it ships `arcana_relay`:
  `arcana_sslproxy_enable`, `_config`, `_fwd`, `_pidfile`; the
  configuration checked by `sslproxy -Q` before each start
  (`configtest`). Enabled, started, stopped by rc.conf and service(8).
- **The configuration**: rendered on the agent from the tab's form
  (job kind `sslproxy`, verb `conf`, the form as JSON) into
  `/usr/local/etc/sslproxy.conf`, checked by `sslproxy -Q -f` before
  it replaces the file; the form kept beside the CA
  (`/usr/local/etc/sslproxy/arcana/spec.json`). An admin's own file is
  not replaced unless asked (force). What the form says: a listener per
  protocol (https, http, smtps, pop3s, its port and the loopback port
  SSLproxy listens on, IPv4 and IPv6), split mode (`Divert no`), the
  NAT engine `ipfw` (the destination by getsockname(2), as `fwd` keeps
  it), `Passthrough` for what cannot be split (client certificates),
  the connect log (on), the content log (off unless asked), and SSH
  logged only: port 22 relayed by a `tcp` proxyspec, which opens
  nothing and writes a connect-log line a session.
- **The CA**: the console keeps one root per tenant fleet (the
  fleet's own when the host has no tenant), made at its first use in
  its data directory, the key never leaving it. The edge's key is made
  on the edge by the `arcana-sslproxy:sslproxy/csr` action (EC P-256,
  `ca.key`, 0600, root's alone; a new one waits as `ca.key.next` while
  the old one serves); the console signs the request as an
  intermediate (CA, path length 0) and installs it with
  `arcana-sslproxy:sslproxy/install-ca`, which takes only a
  certificate of the waiting key, and only a CA's: `CACert`, `CAKey`,
  `CAChain` (the root). One request does both:
  `arcana-console:hosts/host/inspection-ca`. An edge lost gives away
  its own intermediate alone. The root is downloaded from the tab
  (PEM), what the fleet's clients install once.
- **The rules**: `fwd 127.0.0.1,<port>` (and `::1` for IPv6) for TCP
  from the clients (any, or the prefixes given) to `not me` at the
  protocol's port, `in recv` the interfaces given (one at least), in
  ipfw set 27 at rule 7, before the ACLs' entry (8) and the SD-WAN's
  rules (9 to 99), each with a `// sslproxy:<proto>` comment. Loaded
  as the ACLs are: staged in set 26, disabled, swapped in, set 26
  emptied; refused, nothing loaded, when set 26 or 27 holds a rule
  that is not SSL inspection's or another set has a rule at 7. Loaded
  when the service is started (by the agent's job and by the rc
  script at boot), taken away when it is stopped: a stopped proxy
  sends nothing to a closed port. The admin's rules are never touched.
- **The page**: Security, SSL inspection: whether it is installed,
  enabled and running, the form, the edge's CA (subject, issuer, until
  when; Issue or Renew from the fleet's root), the root to download,
  the rules loaded as ipfw lists them, the configuration rendered. The
  FreeBSD facilities named: ipfw `fwd`, sslproxy(1), rc.subr(8).
- **Tests**: agent_test `sslproxy` (a stand-in sslproxy and a stand-in
  ipfw keeping its sets: the rendered file and rules, an admin's rule
  in the way refusing, the CA's key and request, the certificate of
  another key refused); pwa_test `pwa_security_tls` (the form sent, the
  host's file and ipfw's rules checked).

Left by phase 1: rotation of a root (an edge's intermediate is renewed
by Renew), a root's revocation list. Since phase 2, the roots are the
cluster's (below), and an ipfw restart no longer leaves SSLproxy
without its rules; a jail's own SSLproxy is built (Jails, below).

## Phase 2: MEF 138 function policies (the binding built)

TLS inspection is MEF 138's middlebox, the MBSF, a function policy of
an SD-WAN service bound to its zones as the other functions are (its
security policies by af-security-ingress, the end points' policy
maps; one MBSF a zone).

- **Which zones SSLproxy opens**: a zone with an MBSF and nothing that
  needs the requests: no URLF, no MD+R, no DNF name with a `*` inside.
  Those stay on Squid's `ssl-bump` (the MBSF opening TLS there) until
  the URL filter moves (below); Squid no longer takes a zone whose
  only function is its MBSF.
- **Compiled by the console** (sdwan_edge.c, `inspect_build()`) into
  the edge's form: `bound` (the service, the MBSF's ID, the service's
  table), `zones` (each zone's clients, its prefixes at the edge; its
  interfaces, the service's UNIs at the edge; for Default, `except`,
  the other zones' prefixes, skipped first by a `skipto 8`), `mbsf`
  (the policy as the module says it). One SSLproxy an edge: a second
  service, or a second MBSF, with such a zone at one edge fails the
  plan, said. A vnet jail's edge is served by the jail's own SSLproxy
  (Jails, below): its jobs carry the jail, its CA is its own
  (`inspection-ca` with the jail), and the plugin is looked for in the
  jail.
- **The apply**: the edge's CA first where it has none
  (`inspection-ca`, the console's own ask, its intermediate from the
  tenant fleet's root), then the form (job `sslproxy conf`), then
  `enable` (started once, not again where it runs); the object taken
  away, `disable`. The tab shows the binding in place of the form.
- **On the edge** (luxuria/sslproxy.c): the zones' fwd rules in set 27
  at rule 7, as phase 1's; the MBSF as SSLproxy has it: its
  pass-through hosts as `Pass` rules (phase 3: a name exactly, a `*.`
  host its apex and a substring, said), the oldest version
  let through as
  `MinSSLProto` (above every one blocked, and those on no list where
  its No-match blocks), `VerifyPeer no` where a server's certificate
  not trusted is allowed, and cleartext HTTP blocked by an ipfw `reset`
  (`reset6`) rule of set 27 that logs (`log logdst rtsock`). SSLproxy
  runs in the service's table: `arcana_sslproxy_fib`, rc.subr(8)'s
  `${name}_fib`.
- **SENs**: the reset's comment is the one the console's record makes
  a Security Event Notification of (`security <service> <policy>
  unencrypted sslproxy:http`, ipfw's 80 characters allowing; longer
  IDs leave the rule unlogged by SEN, the tag alone): type OTHER,
  "unencrypted HTTP, blocked", the function Middlebox. What SSLproxy
  itself refuses (a version, a certificate) is in its connect log,
  read in phase 4.
- **The rules' tag**: a rule of SSL inspection's is one whose comment
  has `sslproxy:` in it (the SEN's comment starts with `security`);
  the rc script checks the same, and refuses, as the agent does, a
  rule of another set at 7.
- **ipfw restarted**: the agent looks at set 27 every
  `--sslproxy-watch` seconds (30) and loads the rules again where the
  service is enabled and runs, its rules file is not empty and set 27
  holds none of them.
- **The roots in a cluster**: kept in the replicated document
  `inspection-roots.json` (0600, as the credentials are), not in a
  node's own directory: every node signs with the same root, its first
  making under a cluster lock. A root made before (the node's
  `inspection/` directory) is not read.

## Jails (built)

The user's rule: every service feature of Arcana works in a jail too.
One SSLproxy a jail, beside the host's: a host may run several.

- **Installed and read in the jail**: the jail's own sslproxy (`pkg -j
  <jail> install sslproxy`, the tab's Install button with the jail
  picked), found beneath the jail's root without following a link out
  of it (`faccessat(AT_RESOLVE_BENEATH)`), run there by jexec(8)
  (`sslproxy -V`, `-Q -f`). The read, the jobs and the CA's actions take
  the jail (`arcana-sslproxy` read, csr and install-ca `jail`; jobs'
  `jail`; arcanactl `-j`), any running jail, vnet or not.
- **Its files**: sslproxy.conf, spec.json, the CA's files and the rules
  beneath the jail's root, at the paths the jail sees (the agent's
  `--sslproxy-conf` and `--sslproxy-dir`), opened from the root's
  descriptor, never through a link (invidia/scope.c's
  `O_RESOLVE_BENEATH`, `O_NOFOLLOW`): a link the jail's root put there
  refuses the write, nothing is written out of the jail.
- **Its CA**: the key made for the jail (EC P-256) and written beneath
  its root alone, its request named for the host and the jail; the
  console signs it as an intermediate of its own (CN "Arcana SSL
  inspection on <host>/<jail>"), installed there. The key never leaves
  the jail's directory.
- **Its service**: Arcana's rc script copied into the jail's
  `/usr/local/etc/rc.d` (the host's copy, written where it differs), run
  there (`jexec <jid> service arcana_sslproxy`), its variables in the
  jail's rc.conf (`sysrc -j`), the service's table its FIBs.
- **A vnet jail's rules**: its own ipfw's, run in it by jexec, set 27 at
  rule 7, staged by set 26 and refused as the host's are (a rule of
  another's in 26 or 27, or at 7 of another set: the jail admin's left
  alone); the fwd to its own loopback. The rc script in the jail loads
  them at its start; the agent's watch loads them again where the
  jail's set 27 lost them under a running SSLproxy.
- **A jail of the host's network**: SSLproxy listens at the jail's
  address (`ip4.addr`, `ip6.addr`, the first of each; the loopback where
  it inherits the host's); the host's ipfw fwds the clients there
  (`fwd 10.0.0.10,8443`): the destination is a local address, so the
  connection keeps its own, and getsockname(2) on the socket accepted
  in the jail says it (syncache_socket() gives the new socket the
  packet's destination as its local address, the jail's being only
  where the listener was looked up), as SSLproxy's NAT engine `ipfw`
  asks. A jail without an address of a family refuses the form (IPv6:
  give it one, or turn IPv6 off). The rules, tagged `sslproxy:<proto>@<jail>`,
  are the host's: rendered by the agent and kept on the host
  (`jails/<jail>.fwd`, 0600), never read from the jail, whose root may
  write there what it likes; while the jail's SSLproxy is started they
  are `jails/<jail>.rules`, which the host's set 27 is loaded from
  beside the host's own (the agent, the host's rc script at its start
  and stop: `arcana_sslproxy_jails`). The jail's rc script has
  `arcana_sslproxy_fwd` empty and touches no rule. A `deny` rule of
  the jail's listen ports keeps clients from reaching SSLproxy at its
  address but by the fwd (a fwd keeps the packet's destination, which
  the deny does not match). The watch takes a jail's rules out of the
  host's set where the jail or its SSLproxy stopped (its own rc, or the
  jail), and puts them back when it runs again.
- **The page**: a picker on the SSL inspection tab (the host, or a
  running jail); what it reads, sends and issues is the jail's; the
  rules shown are the jail's own ipfw's, or the host's tagged with it.
- **Tests**: agent_test `sslproxy_jail` (stand-in jails, the vnet one's
  ipfw a stand-in apart from the host's), `sslproxy_rc` (the jails'
  started rules); console_test `sdwan_inspect_jail`; pwa_test
  `pwa_security_tls_jail` (a jail picked, its CA, the form, the jail's
  files and its ipfw's rules).

Left: a vnet jail's cleartext-HTTP reset logs to the jail's own
routing socket, which the agent's record does not listen on (no SEN
from it yet); the fwd to a jail's address and getsockname(2) there were
read from the kernel, not tried on one.

## The URL filter's move (planned)

What moves SD-WAN's URLF (and MD+R) off Squid's `ssl-bump`, so that
every zone's TLS is SSLproxy's:

1. SSLproxy 0.10 speaks ICAP (`Icap`, per proxyspec and per filter
   rule): requests (REQMOD) of what it opened to the c-icap Arcana
   already runs beside Squid for MD+R, its responses (RESPMOD) to
   ClamAV's `virus_scan` as today.
2. The URL filter as a c-icap service: `url_check` (c-icap-modules) by
   the zone's lists, its hosts and paths most specific first as
   sdconf.c orders them for Squid, a 403 of its own a block; the named
   lists its files. Its log lines to sdblock.c as Squid's are today
   (the SENs unchanged: the service, the policy, the list).
3. The zone's clients told to c-icap: SSLproxy's `IcapSanitizeRequestLine`
   off and `X-Client-IP` (ICAP's client header), matched to the zone by
   prefix as sdblock.c does.
4. The `fwd` rule then in the service's SD-WAN rules (set 9 to 99),
   where Squid's 3129 is today, after the IPS divert, so that the
   IPPF's and IPS's rules come first; set 27 kept for the tab's form.
5. One SSLproxy a service (profiles of the rc script,
   `arcana_sslproxy_profiles`, each its FIB), lifting phase 2's one
   service an edge.
6. Squid's `https_port … ssl-bump` and its CA (`sdwan-sw<fib>-ca`)
   removed; Squid keeps cleartext HTTP alone, or goes when url_check
   takes HTTP too (SSLproxy's `http` proxyspec).

## Phase 3: what is not opened (built)

A do-not-decrypt list, the tab's form's and an MBSF's alike, rendered
by the agent (luxuria/sslproxy.c) two ways: what SSLproxy must see to
tell (a name) as its filter rules, what ipfw can tell (an address, a
port) by rules that never send it to SSLproxy.

- **Hosts, names and `*.` wildcards**: SSLproxy 0.10's filter rules
  in their one-line form, `Pass to sni <name>`, what `PassSite` was in
  the syntax that replaced it. Its matcher (src/filter.c) takes a name
  exactly or, with a trailing `*`, any name that *contains* the rest
  (an Aho-Corasick keyword, the first found returned, so no guard rule
  can fence one): a leading `*` is no pattern (a literal
  `*.example.org` matches nothing), no anchored suffix, no regex.
  A `*.example.org` host is therefore rendered as two rules,
  `Pass to sni example.org` (the apex, exactly) and
  `Pass to sni .example.org*` (any name containing `.example.org`, the
  leading dot keeping `evilexample.org` out). It passes the domain and
  every name beneath it, and also any name made to contain it
  (`www.example.org.attacker.example`): a way past inspection the
  admin is told of where they see the list, not a refusal (the user
  wants wildcards: 2026-11-20). The form's help beside the field (the
  tab's and the SD-WAN MBSF's), a note on the tab's binding, the
  console's plan note for a zone SSLproxy opens, and a comment in
  sslproxy.conf say: SSLproxy matches `*.example.org` as a substring,
  `example.org` and its subdomains pass, and so would
  `www.example.org.attacker.example`; a zone opened by Squid has an
  exact wildcard (its `ssl::server_name .example.org` is anchored,
  unchanged). A `*` alone (every site) and a `*` anywhere but a
  leading `*.` are refused, by the agent and the console. 64 at most.
- **The CN only where verified**: `Pass to cn <name>` (the server
  certificate's CN, for a client without SNI) is written only where
  `VerifyPeer yes` (the tab's form, an MBSF whose
  invalid-server-certificate blocks); under `VerifyPeer no` the CN is
  whatever the server says, so the hosts pass by SNI alone.
- **Arcana's categories** (`cats[]` in sslproxy.c), opt-in: off unless
  the form names them, exact names each, no third party's feed:
  - `os-updates`: FreeBSD's pkg, update and download hosts (both
    cases: SSLproxy is not known to fold case, and a client may send
    the URL's), Windows Update's and Apple's software update hosts:
    signed payloads, often pinned clients;
  - `pinned`: Apple's push (`api.push.apple.com`), Google's FCM
    (`mtalk.google.com`), Signal's and WhatsApp's endpoints, which pin
    their certificate and break rather than be seen.

  Banks and clinics are no category: no exact list of them is an
  edge's to ship (the registry-verified top-level domains were tried,
  but only as a substring pattern), so they are the admin's own names,
  or a feed the admin chooses later (not built). An update or pinned
  service on a name not listed is opened; the lists are short on
  purpose. The console is not in them: its rp_id may be a parent
  domain of its name; the admin adds its name.
- **Destinations, ports, clients**: `skipto 8` rules ahead of each
  zone's fwd, per family and interface, tagged `sslproxy:pass`
  (`@<jail>` for a jail of the host's network): the clients never
  opened (`from <prefixes> to not me <the inspected ports>`), the
  destinations (`from <the zone's clients> to <prefixes> <ports>`), the
  ports (`to not me <ports>`). SSH's relay port is not among the
  inspected ports: it is logged, not opened. 32 prefixes of a family
  each (one ipfw rule takes them).
- **The console's prefix lists** (prefixlists.c): on the tab, picked
  beside the clients inspected and beside the clients never opened,
  their prefixes written into the form when saved (as the other pages
  take them); in an MBSF, `pass-client-lists` names them and the console
  writes their prefixes into the edge's `pass-clients` at each apply, so
  a list changed reaches the edges at the next.
- **The model**: MEF 138's MBSF has its pass-through hosts (Arcana's
  leaf already, phase 2); beside it, Arcana's own: `pass-destinations`,
  `pass-ports`, `pass-clients`, `pass-client-lists`, `pass-categories`
  (`os-updates`, `pinned`; absent: none), in arcana-l3nm's
  security-function-policy and the document. One MBSF a zone, so a
  zone's exceptions are its MBSF's; the tab's form has the same as
  `pass`, `pass_destinations`, `pass_ports`, `pass_clients`,
  `pass_categories`.
- **Squid's zones** (an MBSF beside a URLF or MD+R): the same list
  spliced (`ssl_bump splice`): hosts and categories by
  `ssl::server_name` (each once, case aside), destinations by `dst`,
  ports by `port`, clients by `src` (arcana-sdwan's mbsf-form).
- **The page**: the tab's form has a "Never opened" fieldset (the
  categories, hosts, destinations, ports, clients and the console's
  lists); the binding shows what the MBSF never opens; the SD-WAN
  function policy's form has the same for an MBSF.
- **Tests**: agent_test `sslproxy` (no category unless named, the
  form's list, a name containing a passed one looked up and opened, a
  `*.` host's two rules by SNI and CN, the model passing the apex, a
  subdomain and, as documented, `www.example.org.attacker.example`,
  `evilexample.org` opened, a `*` alone refused, what is wrong),
  `sslproxy_bound` (the MBSF's, no CN rule under `VerifyPeer no`, a
  `*.` host's two SNI rules), `sslproxy_jail` (a
  vnet jail's and a shared jail's), `sdwan_forms` (Squid's splices);
  console_test `sdwan_inspect` (the list compiled, a prefix list
  written out, what is wrong refused, a `*.` pass-through sent with
  the plan's note, a `*` alone refused); pwa_test `pwa_security_tls`
  (a `*.` host saved, the help shown, the conf's two rules),
  `pwa_security_tls_jail`, `pwa_sdwan_inspect` (the forms submitted,
  the host's and the jail's files checked).
- **Not tried on a real SSLproxy**: the tests' sslproxy is a stand-in
  that takes any file, and the lookup in the agent's case is a model
  of SSLproxy's matcher (exact, or a trailing `*` a substring, case
  kept), as upstream's documentation has it (no sslproxy on the build
  host to read); that 0.10 takes `Pass to sni`/`Pass to cn` as
  written, and has no anchored matcher this missed, wants `sslproxy -Q -f` of the rendered file on a host with
  security/sslproxy installed.

Left for later: per-site exceptions from a connect-log line ("never
open this one", phase 4 reads the log first); a category feed the
admin names (one of the console's lists, by name); ipfw tables for
client and destination lists longer than one rule takes.

## Phase 4: what happened, told (planned)

The connect log read as eve.json is: each connection opened, passed,
blocked or failed counted, a failure an event (`tls-inspect`); the
mirror to Suricata (`MirrorIf` over an epair(4)) for plaintext IDS;
SSH sessions from Suricata's records and sshd's `LogLevel VERBOSE`.
With it, phase 3's leftovers: a connect-log line's "never open this
one" (its SNI into the tab's hosts, or the MBSF's pass-through), and
the passed connections counted by the rule that passed them (the
category, the admin's host, a skipto's counters).
