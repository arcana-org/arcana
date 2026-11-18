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

Left by phase 1: a jail's own SSLproxy (a vnet jail's network), the
console cluster's other nodes holding the roots (they are the node's
that made them), rotation of a root (an edge's intermediate is renewed
by Renew), a root's revocation list.

## Phase 2: MEF 138 function policies (planned)

TLS inspection as a security function of the SD-WAN's services: a
function policy (MEF 138) of the kind that inspects, bound to a
service's zone as the URL filter's are, compiled by the console into
the edge's form (its clients the zone's prefixes, its interfaces the
UNIs) instead of one typed on the tab. SD-WAN's url-filter criterion
then moves from Squid's `https_port … intercept ssl-bump` to SSLproxy,
the `fwd` rule in the service's FIB (setfib(2)) as Squid's intercept is
today; SENs for what SSLproxy blocked or could not split.

## Phase 3: what is not opened (planned)

- A do-not-decrypt list: SSLproxy `Pass` rules (`PassSite`, by SNI and
  certificate CN), Arcana's small default (the FreeBSD update and
  package servers, the console) and the admin's own; destination
  prefixes from the console's prefix lists. No category feed (a third
  party's) by default; categories only from a list the admin names.
- Per-site exceptions from the tab and from a connect-log line ("never
  open this one").
- The clients by source class: the console's prefix lists as the
  `fwd` rules' sources.

## Phase 4: what happened, told (planned)

The connect log read as eve.json is: each connection opened, passed,
blocked or failed counted, a failure an event (`tls-inspect`); the
mirror to Suricata (`MirrorIf` over an epair(4)) for plaintext IDS;
SSH sessions from Suricata's records and sshd's `LogLevel VERBOSE`.
