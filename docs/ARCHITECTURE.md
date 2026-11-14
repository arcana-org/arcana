# Arcana architecture

Arcana manages a fleet of FreeBSD hosts: an agent on each host, and a
console that coordinates them for its users.  The vocabulary of Archives,
Agent and Orchestrator is in [NAMING.md](NAMING.md).

## Programs

Each program does one thing.  There is one daemon per role.

| Program | Runs on | Does |
|---|---|---|
| `arcana-agent(8)` | every host, as root | Serves the host's YANG models over cblink's YANG family: reports jails and the rest and changes them. The only privileged component. |
| `arcana-console(8)` | the console host, unprivileged | Its own HTTP server on libwebsockets: serves the PWA and its JSON API, authenticates you with WebAuthn, talks to `arcana-agent` instances as a cblink client. |
| PWA (C → wasm) | the browser | The console. |
| `jailconf(8)` | anywhere | Adds or removes a value of one jail's parameter in jail.conf, in place, like sysrc(8) does for rc.conf. |
| `arcanactl(8)` | anywhere | Command-line client for `arcana-agent`. |
| `arcana-enrol(8)` | a host, once | Gets the host a certificate from the console's CA with a one-time token, and starts `arcana-agent` with it. |

```
 browser                 console host                         hosts
┌──────────┐  HTTPS   ┌──────────────────────┐  cblink     ┌──────────────────────┐
│ PWA      │ ───────▶ │ arcana-console       │ ──────────▶ │ arcana-agent         │
│ C → wasm │   JSON   │ WebAuthn, sessions,  │ TCP, mTLS   │ libjail, libprocstat │
│          │ ◀─────── │ server registry      │ ◀────────── │ jail(8) -e / -c / -r │
└──────────┘  cookie  └──────────────────────┘    CBOR     │ libjailconf          │
                                                           └──────────────────────┘
                                         arcanactl ─────▶ (the same models, for admins and tests)
```

When the console host also has jails it runs both: the web-facing
process stays unprivileged and reaches the local `arcana-agent` over an
AF_UNIX socket.

## The wire: YANG

The contract between `arcana-agent` and its clients is its YANG models
(`share/yang`): the standard ones (RFC 8343's interfaces, RFC 8349's
routing, RFC 8341's NACM...) with Arcana's augments, and a module of
Arcana's where none exists, each with its SIDs (RFC 9595,
`share/yang/SIDS.md`).  They travel as YANG-CBOR (RFC 9254) on cblink's
YANG family: GET of a datastore, EDIT of the candidate and a confirmed
commit, an rpc or an action, RFC 8639 subscriptions; cblink-gen(1)
writes the C structures, the schema tables and the server's
trampolines from the modules (`share/mk/arcana.yang.mk`).  Beside it
the agent has two families of its own, for streams alone: `arcana-
stream` (a snapshot sent or received, a capture put or a pcap-log
file got) and `arcana-parts` (a network table in parts).  The steps a
request takes are told to its peer as it runs, arcana-jobs' `steps`
notification.

`share/arcana/arcana.yaml` is no family any more: what the programs
keep for their own use (a jail, a service, a job and the change it
makes, the kinds of job), from which `share/arcana/wire.awk` writes the
module `arcana@<rev>` of structures alone and the header that names
them (`arcana.h`); `share/arcana/jobs.awk` makes arcana-jobs' kinds of
it and `jobs.yaml`.  The consoles' own family, `cluster.yaml`, is a
family as it was, built only with `WITH_CLUSTER` (the port's `CLUSTER`
option, off by default): without it `nodes.c` and its Raft, `craft.c`,
and the family are left out, nothing of it listens, and `nocluster.c`
answers in their place as a console that is no cluster's (a `cluster`
block in `web.conf` stops it, naming the build).

The core operations, and what each runs on the host (the rest are in
`share/arcana/yang-ops`, each with its module):

| Operation | Does | Mechanism in `arcana-agent` |
|---|---|---|
| arcana-host `host` | host facts, the agent's features | uname(3), sysctl(3) |
| arcana-jails `jails` | running and configured jails | jail_getv(3), procstat_getprocs(3), `jail -f scope -e sep` |
| arcana-jails' `start`, `stop`, `restart`, `kill` | a jail's actions | jail(8) `-c`, `-r`, `-rc`; jail_remove(2) for kill |
| arcana-network's `address` | add or remove an IP, live and/or persistent | jail_setv(3), SIOCAIFADDR ioctls, libjailconf |
| arcana-services `services` | the host's rc.d scripts, enabled and running; in running, each one's rcvar and variables | the rc.d directories, `<name>_enable` in `sysrc -A`, `service <name> status`; the files rc(8) reads (libvarconf) |
| arcana-services' `start`, `stop`, `restart`, `reload`, `read` | a service's actions; one read as it is now (an operator's; a viewer's what the agent last saw) | `service <name> <verb>`; `service <name> enabled`, `describe`, `extracommands` |
| arcana-services, committed | enabled or not, its rc.conf variables | Arcana's rc.conf file (`/usr/local/etc/rc.conf.d/arcana`), yours commented out where accepted |
| arcana-network's read actions | routes, nexthops, connections, sockets | `netstat --libxo json -rnW / -onW / -nW -f <family>`, `sockstat --libxo json -w -4/-6`; one run per family, joined |
| arcana-host `stats` | CPU, load, memory, swap, ZFS pools | `kern.cp_time` between requests, `vm.loadavg`, `vm.stats.vm.*`, `swapinfo -k`, `zpool list -Hp` |
| arcana-packages `packages` | pending upgrades of the host or a running jail | `pkg [-j jail] update -q`, `pkg [-j jail] version -vRl '<'` |
| arcana-packages' `upgrade` | upgrade all or named packages, or show what would be | `pkg [-j jail] upgrade -y|-n [names]`, then `pkg version` again |
| arcana-jobs `submit` | queue a batch of changes | the job queue, below |
| arcana-jobs `jobs`, its `read`, `cancel`, `confirm` | list jobs, read one with its trace so far, take a queued one back, keep a safe change | the job queue |

Every request requires an authenticated peer: a client certificate
from the arcana CA that says urn:arcana:role:console over TCP or SCTP,
or access to the 0600 AF_UNIX socket; a host's certificate
(urn:arcana:role:agent), or one that says neither, asks nothing.  What
it may do is NACM's (RFC 8341): what changes the host, runs a program
with arguments its caller chooses, makes the host reach out, or gives
out what should stay on it, is `nacm:default-deny-all`, run only by a
rule that permits it (`make check-nacm` holds every action and rpc of
Arcana's modules to it, or to `share/arcana/nacm-allow` with why it
only reads).  The console's nacm-sync puts its owners in the host's
group admin, and its operators of the host in its group operator, with
a rule-list that lets them what an operator may and the host marks
(arcana-system's read).  With the hosts' default for actions deny
(Settings, AAA, Roles), it also writes exec-default deny and the
rule-list every-role: for every user, a permit of each action of
nacm-allow, which nacm.awk writes into the console's nacmallow.h at
the build, so the list and the permits are one; the group admin keeps
its permit-all, and the recovery session is no NACM's.  A read that
runs a program a jail or a local user controls (a service's rc.d
script, a vnet jail's own ipfw, swanctl, ifmcstat, birdc, wg or sysctl
by jexec) is an operator's: a viewer gets what the agent collected, or
the refusal.  A refusal comes back with its words, and the
steps told while it ran, so a failed jail(8) run still comes back with
its output.

Reading configuration goes through jail(8) itself (`-e`), so variables,
includes, `*` blocks and per-jail `jail.conf.d/<name>.conf` files mean
exactly what they mean to jail(8).  libjailconf exists only for the one
thing jail(8) cannot do: change a value in place.  It parses a file only
to find the jail's block and the bytes to change; what the jail already
has or inherits it is told, from `jail -e`.  After writing,
`arcana-agent` reads the file back with `jail -e` and restores the previous
version if jail(8) disagrees with the edit.

The console's northbound is RESTCONF (RFC 8040), each host's agent
mounted below `arcana-fleet:fleet/host=<id>` (RFC 8528).  Between its
JSON (RFC 7951) and the agents' YANG-CBOR stands one translator,
cblink's (`<cbl_yxlate.h>`), driven by a schema's SIDs as the peer
numbers them (`cbl_ysids`: its `.sid` files resolved to the console's
tables by identifier): names from the peer's files, types from the
console's tables where they have the node, CBOR's or JSON's own kind
where they do not; annotations, origin among them, as RFC 7952's `@`
members.  A client that asks for `application/yang-data+cbor` gets the
agent's YANG-CBOR as it came (`id=sid`); the page reads it by the
host's `.sid` files (`www/arcana-ui/src/ycbor.c`).  Each host is read by
its own schema (`ycache.c`): its agent's YANG library and `.sid` files,
kept by its address and checked again when a new connection reaches it
(an agent of another release has other modules), so a path, a reply and
an edit are the host's own, whatever release the console is.

## Library choices

Base system first; packages only where they remove real work.

| Need | Library |
|---|---|
| Jail state and changes | libjail(3) (base) |
| Per-jail processes | libprocstat(3) (base) |
| Interface aliases | ioctl(2); libifconfig is internal to base, with no header |
| JSON (backend, frontend) | libucl (base, `libprivateucl`); the frontend compiles the same sources to wasm |
| Text sanitising | vis(3) (base) |
| WebAuthn signatures | libcrypto (base OpenSSL); browsers hand the public key over as SPKI DER, so no CBOR decoding is needed |
| Host transport | cblink (libcblink, needs the libcbor package) |
| Tests | ATF: atf-c(3), atf-sh(3), kyua(1) (base) |

## Trust boundaries

| Component | Privilege | Holds |
|---|---|---|
| Browser | none | an HttpOnly, SameSite=Strict session cookie |
| `arcana-console` | unprivileged user (its supervisor root, to listen and read the HTTPS key) | the users, their roles and WebAuthn public keys, its cblink client certificate and key, and the CA's key when it runs its own CA |
| `arcana-agent` | root | its server certificate and key, the CA certificate |

## Authentication (browser to console)

Users, each with one or more WebAuthn credentials (a security key and
a spare), and roles that say what each may do on the console and on
which hosts (`users.json` in the data directory).  A user may belong to
a tenant, a fleet of its own, and then sees that tenant's hosts alone,
adds hosts to it alone, and its workflows, runs and templates; the
SD-WAN and its services (the L3NM, the virtual networks) are one
document for the whole fleet, and so not a tenant's user's.

* **Enrolment.**  Until the console is set up (a key stored, or a user
  with a password), the backend writes a random one-time setup token to
  `<datadir>/setup-token` (mode 0600).  The first registration needs it
  and makes the built-in owner, or, set up by a password instead, the
  token, a user name and a password make that user an owner; an invited user
  registers with the invitation's token; adding a key needs a logged-in
  session.
* **Ceremonies.**  Single-use challenges, valid two minutes, kept
  nowhere: each says when it ends and, a registration's, whose key it
  is and by which invitation, under a MAC of the console's; noted used
  once its ceremony succeeded, and an invitation spent only by the key
  it registers.  The backend checks `clientDataJSON` (type, challenge,
  origin) and the authenticator data (RP ID hash, flags, counter) and
  verifies the signature with libcrypto.  ES256, EdDSA and RS256.
  A sign-in's start names no key: the authenticator offers the
  passkeys it holds (registration asks for one, `residentKey`
  preferred), and the credential it answers with names the user.  A
  user name sent with the start (a key that keeps no passkey) gets
  that user's keys, and a name with none as many ids made by HMAC of
  the name with a secret of the console's (`credentials.json`), the
  same each time, so the reply tells not who is there; a named start
  waits while the name or the address is throttled, and is a try of
  the address's.
* **Passwords.**  A user may also sign in with a password of the
  console's own (bcrypt) or, when **Settings** name a directory, by LDAP
  over TLS.  A session opened by the console's own password has the
  user's roles, unless `web.conf` says `password_full = false`; one
  opened by the directory's, and the console's own then, cannot change
  sign-ins, tokens, users, the CA, the settings or enrol hosts; that
  takes a key.  A directory's user the directory gives no role on the
  console is refused, and so is a directory account whose name is a
  local user's (the built-in owner's among them): the directory signs
  in its own users alone, and a local user is not made of a directory
  user's name but by removing that one first.  Directory users are of
  no tenant: a role their group gives with "*" for its hosts is every
  tenant's hosts (docs/TODO.md).  Failed sign-ins wait by the name
  tried from one address (5 a minute), by the name from every address
  (50) and by the address (20), never for everyone; the setup token's
  tries have a count of their own; bcrypt and the directory run in a
  task, never on the server's loop, a password set or checked as one
  signing in.  One's own password is changed with the current one, or
  with a key of one's own over a challenge made for that (the user in
  it, under the console's MAC, used once): a session left open is not
  enough; an owner sets another's.
* **Users and tenants.**  Each user has a stable id beside its name
  (`users.json`, made with the user): a session, a token's maker and a
  stored intent's author name it, so that a user removed and another
  made with the name is not taken for them.  A tenant's user is a
  console operator at most: the tokens, users and settings are every
  tenant's.
* **Sessions.**  32 random bytes in a cookie; only its SHA-256 is kept.
  Idle timeout 30 min, absolute 12 h.  As many as are open, 4096 at
  most; a user (or a token) has 16, their own oldest ending when they
  open another.  The key, user, token or password a session was opened
  by, removed, ends it.  A WebSocket or an event stream is bound to
  the session (or token) that opened it, judged again at each message
  and record when who may do what changed or its session's end is due,
  and closed with it; a host its principal may no longer read is read
  no more.  8 streams of one principal at once (a token's from one
  address), an event stream an hour at most, then made again by the
  browser.  One guard checks every protected
  route, by one table of who may touch which of the console's own nodes
  (`cnodes.c`: each node or subtree's role to read and to write it,
  whether it is the whole fleet's or every tenant's alike, so no
  tenant's, and what an API token does with it), a user judged by
  their role and tenant, a token by its kind and its maker's role and
  tenant; `make check-cnodes` has every node and action of
  arcana-console in it.  A client of a unix listener (0660, the
  console's user's and `listen_group`'s) is known by its uid,
  `unix:<uid>`, to the throttle; a request on one is judged by its
  `Origin` as any.  State-changing requests also need the console's own `Origin`
  (a browser sends it), or `X-Arcana: 1` from a client that sends no
  `Origin`.  A GET changes nothing, so it needs neither, even where a
  read is kept to the roles that may change (a host's system files).
* **Whom for.**  What the console asks of a host is asked for one
  principal (`hosts.c`): a console user, held to the role it needs on
  that host (`users.c`) and, there, to the host's access rules by
  name; an API token, held to its own reach (a read token a viewer's,
  a write token an admin's), never more than its maker may now, a host
  at a time, and said to the host as what it may there: a read token
  as the NACM user `token-read`, in no group (a viewer: secrets
  masked, BIRD's texts and the services' values left out), a write
  token as its maker (the built-in owner for one made before tokens
  kept a maker), the host's rules for that user holding it; or the
  console itself, said as `console` (group admin by the agents'
  default), which only the paths that act for no one take (the
  subscriptions' connections, the notifier's and the workflows' event
  reads, the SD-WAN manager, the threat feeds' delivery, the alert
  channel, the hosts' roles synchronized).  `console` and `token-read`
  are no user's names: the console makes no user of either, its
  nacm-sync takes `token-read` out of every group, and an agent holds
  `token-read` to a viewer whatever its rules say.  What the console does by itself is
  bounded by who asked for it: the SD-WAN manager works from the L3NM
  as a user last applied it (each edge it changed theirs to change),
  never from what is kept and not applied, an identity run out taken
  away on its edge alone; a threat feed goes to the hosts its author
  (who last saved it) may operate at each delivery, the others skipped
  and said so.  A change of the SD-WAN document or the L3NM is the
  writer's on each edge it reaches at any depth, kept with who made
  it.  A
  thread starts acting for no one and asks no host anything until told
  whom for; one started by `hosts_thread()` acts for its starter.  A
  workflow runs for who started it, or, by itself, for who last saved
  it, on each host as that user may, or fails and says why.
* **Headers.**  Every reply, the page's and the API's: a
  Content-Security-Policy (only the console's own scripts, styles, images
  and connections; WebAssembly, by `'unsafe-eval'` for the browsers
  that do not know `'wasm-unsafe-eval'`; no framing), `X-Frame-Options: DENY`,
  `Cross-Origin-Resource-Policy` and `Cross-Origin-Opener-Policy`
  `same-origin`, `X-Content-Type-Options: nosniff`, `Referrer-Policy:
  no-referrer`, a Permissions-Policy allowing passkeys, fullscreen and
  the clipboard alone, and over TLS `Strict-Transport-Security` for
  this host only, as many days as the setting `hsts_days` says (365
  unless set; 0 sends none).

## Console plugins

Extensions of the console's page, served by the console from its own
origin (`cplug.c`); not the hosts' plugins (BIRD, Suricata and the
others), which run on the hosts.  Only what the console host's
administrator installed and a console owner enabled is served.  A
plugin is data or trusted:

* **Data**: themes and guide packs, JSON and pictures (and a font) that
  the console checks and the page applies with its own code; nothing of
  the plugin's runs.  The common kinds need no more.
* **Trusted**: a plugin with scripts (`entry`) or stylesheets
  (`styles`).  Its script runs with the page's full rights, those of
  every user who opens it, with their session; the manifest says
  `"trusted": true` or the plugin is refused, and Settings shows it
  apart, under a warning, and asks before enabling it.  It may ship
  themes and guide packs as data too.

* **Where.**  A directory each under web.conf's `plugins_dir`
  (`/usr/local/share/arcana-console/plugins` unless set; `""`, or no
  such directory, for none), named by the plugin's id.  A link to a
  directory elsewhere is not a plugin.
* **Format.**  `plugin.json` in it: `id` (`[a-z0-9-]{1,40}`, the
  directory's name), `name`, `version`, `arcana` (the least console
  version, `a.b.c`; an older console lists the plugin with why and
  serves none of it), optional `description`, `author`, `themes`
  (`[{id, name, file}]`), `guide-packs` (`[{id, name, expressions,
  lines}]`), `trusted`, `entry` (the `.js` files, in order), `styles`
  (`.css`), `assets` (files or glob(3) patterns of `.png`, `.svg`,
  `.webp`, `.json`, `.woff2`) and `provides` (words: `theme` exactly
  when it has themes, `guide-pack` exactly when it has guide packs; a
  data plugin nothing else).  `entry` or `styles` without `"trusted":
  true`, `trusted` without them, anything else, a key the format does
  not have, a path that is absolute, hidden or has `..`, a file larger
  than 8 MB, a file whose real path is out of the plugin's directory (a
  link out), data that is not as below, and the plugin is listed with
  the reason and none of it served.  The files of its themes and guide
  packs, and `plugin.json` itself, are listed with its assets.
* **A theme's file**: `{"scheme": "dark" | "light", "tokens": {...},
  "font": {"family", "file"}}`, tokens required.  A token is one of
  `web/style.css`'s `:root` custom properties that a theme sets (the
  table in `cplug.c`, the same in `bridge.js`), each by a grammar of its
  own: the colours (`--bg`, `--fg`, `--cyan`, ...) `#rgb`, `#rgba`,
  `#rrggbb`, `#rrggbbaa`, `rgb(r, g, b)` or `rgba(r, g, b, a)`; the
  channels (`--accent-rgb`, ...) `r, g, b`; the faces (`--sans`,
  `--mono`, `--display`) up to eight names, quoted (letters, digits,
  spaces, `-`) or bare, by commas; `--cut` and `--radius` `0` or a
  number of `px`, `rem` or `em`.  Nothing else: no `url()`, no `var()`,
  no `@import`, nothing that fetches.  The font a `.woff2` it lists.
* **A guide pack's files**: `expressions.json` (`version`, `default`,
  `expressions`, and one of `rig`, an `.svg`, or `images`, an `.svg`,
  `.png` or `.webp` an expression), `lines.json` (`version`,
  `placeholders`, `moments`: lists of `{expression, text}`), each picture
  a file the plugin lists, relative to its JSON; every string text of
  300 bytes at most, shown as text and never as markup.
* **Hashes.**  Each listed file's size and SHA-384 are kept; the page
  loads exactly these, with `integrity="sha384-..."`.  The directory is
  looked at again at most once a second, on a read of
  `arcana-console:plugins` and on a
  plugin's file asked for: rescanned when it, a plugin's directory,
  its `plugin.json` or the directory of a listed file changed, and a
  listed file whose time or size changed is hashed again; a theme's or
  a guide pack's file that changed is checked again, the plugin
  rescanned, and not served as it is until then.  No restart.
* **Enabled** by a console owner alone (`plugins/plugin=<id>/enabled`
  of `arcana-console`), kept in `console-plugins.json` in the data
  directory, written in the audit trail.  An enabled plugin is served
  to every signed-in user.
* **Served** at `/plugins/<id>/<file>`: a file the plugin lists, of an
  enabled plugin, to a session (not to an API token), with the
  headers every reply has (above), `Cache-Control: no-cache` and the hash as the
  ETag; read and hashed again as it is sent, its real path checked to
  be in the plugin's directory.  An SVG with a policy of its own too
  (`default-src 'none'; style-src 'unsafe-inline'; img-src data:;
  sandbox`) and `Content-Disposition: attachment`: a picture for an
  `<img>`, which opened by its address runs and fetches nothing and is
  saved, not shown.  Anything else is not found.
* **Loaded** by the page (`bridge.js`, `plugins.c`) once signed in:
  the list is read then and again with the health (every 15 s while
  the page is looked at), and each enabled plugin with no error that
  the page has not loaded yet gets its data read (`fetch` with the
  integrity: `plugin.json`, then its themes' and guide packs' files),
  checked by the same rules and applied by the page's own code, all or
  nothing; a trusted one its styles too (`<link rel=stylesheet
  integrity crossorigin>`) and its scripts (`<script integrity>`, in
  `entry` order).  No `<script>` is made for a data plugin.  A theme is
  picked in Settings, Look (kept in the browser as `p:<plugin>/<id>`)
  and worn by setting its tokens on `:root` over the stylesheet's; a
  guide pack goes to a guide's runtime (`guide-packs` below) and is
  shown in Settings, Plugins (its picture an `<img>`, its first line as
  text).  A file the browser refuses (its bytes not what was listed),
  data the page refuses, a script that throws, a plugin function that
  throws: the plugin's error, shown in Settings, Plugins and in a
  toast; the page goes on without it.  Enabled, a plugin is loaded at
  once; disabled, its themes (worn or not) and guide packs are put away
  at once, and a trusted one's code stays in a page until that page is
  loaded again (Settings says so).  Settings, Plugins lists the data
  plugins, then the trusted ones apart under a warning (name, version,
  author, provides, enabled, and what the page made of each) and has
  Enable and Disable for a console owner; enabling a trusted one asks
  first.

The page gives a trusted plugin's scripts `window.Arcana`:

| Member | What |
|---|---|
| `version` | the console's version |
| `user` | `{name, role}` of who is signed in |
| `registerPlugin({id, screens, menu, on})` | once, from the plugin's own script, `id` its own; `on` as `Arcana.on` for each key |
| `guidePacks()` | the guide packs of plugins' data, `[{id, name, plugin, base, expressions, lines}]`, the files relative to `base`, for a guide's runtime to register |
| `api(method, url, body)` | a request to the console as the page makes them (its session, `X-Arcana`), a path of the console's alone; `body` sent as JSON; a Promise of the reply's JSON, rejected with an `Error` (`status`, `body`) unless 2xx |
| `navigate(hash)` | goes to an address of the page (`#/...`) |
| `toast(text, bad)` | a toast, an error's when `bad` |
| `fullscreen(on)` | the page over the whole screen, or not, where the browser lets it |
| `store.get()`, `store.put(obj, etag)` | the signed-in user's own JSON object for the plugin (below): `get` resolves to `{data, etag}`, `data` `null` while none is stored; `put` to `{etag}` |
| `store.shared.get()`, `store.shared.put(obj, etag)` | the same, one object the console's users share: any console role reads it, an operator or an owner writes it |
| `on(event, fn)` | `route` (`{hash}`, the address once it changed, after what the page does then: the last told is the address, the same one never twice in a row), `theme` (`{theme}`), `servers` (`[{id, name, local}]`, when the hosts change, and at once with them as they are), `signed-out`, `gamepad-first` (`{id}`, a controller's first press on the console's pages; a handler that returns `true` takes it, and the page does nothing with that press), `guide-packs` (`guidePacks()`'s list, at once and whenever a data plugin's packs come or go) |

`screens: {<name>: {title, enter(root, ctx), leave()}}` are the
plugin's screens, at `#/p/<plugin>/<name>[/<rest>]`: shown, the page's
own regions are put away and its controller overlay is off (the screen
reads the Gamepad API itself), `enter` gets a root element over the
whole page and `ctx` (`plugin`, `screen`, `rest`, `exit()` back to the
page as it was); `leave` is called when another address is gone to.
The rest of the address is the plugin's: `route` tells it when it
changes.  `menu: [{label, screen}]` adds entries to the account menu
that open a screen of the plugin's.

`Arcana.store` is where a plugin keeps what it keeps of a user (their
progress, their choices) or of all its users: not for secrets, which
every script of the page, any plugin's, can read.  On the console it
is `GET` and `PUT` of `arcana-console:plugins/plugin=<id>/store` and
`.../shared-store`, to
a signed-in user's session alone (not an API token), only while the
plugin is enabled and has no error (404 else); each a JSON object of
16 KB at most (400 for anything else, 413 beyond), kept in
`plugin-store/` of the data directory as `<plugin>.user.<user>.json`
(the user's `_`, `.` and `@` written `_5f`, `_2e`, `_40`) and
`<plugin>.shared.json`, written whole under a lock, through the
cluster when there is one.  Each is tagged by an ETag, the SHA-256 of
its compact JSON: a `put` names the `etag` it read (`If-Match`), and
one made without an `etag` is a first write, done only while nothing
is stored yet; otherwise it is refused with 412 (the Promise's
`Error` has `status`), and the plugin reads again and merges.  A
user's stores go with the user; a plugin's stay while it is disabled,
and are there again when it is enabled.

## Enrolment (host to console)

Without a `tls { }` block the console runs its own CA (`pki.c`): EC
P-256, made at first start in the data directory, with the console's
client certificate signed by it.  A logged-in user asks for a token for
a host (`arcana-console:enrolment/create-token`: name, host, port); it
is `arce1_` and base64url of 32 random bytes and the SHA-256 of each
root of the CA (the console keeps the random bytes' SHA-256 alone),
single use, valid an hour: one pasted text lets the host in and pins
the CA it will trust.  `arcana-enrol(8)` on the host makes
a key and a certificate request and sends them with the token (`POST
/api/enrol`, no session).  The console signs a certificate for the
token's host, whatever the request's subject says, with `serverAuth` and
a SAN for the host, returns it with the CA, and adds `tcp://host:port`
to its servers; `arcana-enrol` writes nothing unless each certificate
of that CA is one the token (or `-f`) pins.  The host's key never
leaves the host.

## Trace model

Every reply that touched a host carries a trace: steps with a parent,
forming a tree.  `arcana-agent` records its own steps; the backend adds the
API, session check and cblink request steps above them.

```
POST .../host=s1/arcana-jails:jails/jail=web/restart   api
├─ session check                                auth
└─ libcblink YANG action tcp://host:4310      lib   libcblink, mTLS
   └─ arcana-agent jail web restart               daemon
      ├─ /usr/sbin/jail -f … -e \037            exec  (read configuration)
      ├─ jail_getid(3)                          lib
      ├─ /usr/sbin/jail -f … -rc web            exec  (the restart)
      └─ jailparam_get(3)                       lib
```

`kind` is `api`, `auth`, `daemon`, `lib`, `syscall`, `file` or `exec`.
Only `exec` steps carry `argv`, `exit`, `output` and `error-output`; the
UI shows its raw-output button exactly when a trace has one.  Because
configuration is read through `jail -e`, any request that reads
configuration has one.  Program output reaches the browser with
unprintable characters as vis(3) escapes (the `-e` separator shows as
`\037`).

## Jobs

A change that is asked for and waited on dies with its connection. That
is wrong for exactly the changes that matter most: restarting the jail
the console runs in, or the interface it is reached through. So every
change can instead be **queued as a job** (arcana-jobs' `submit`, one or a batch
of up to 64).

The daemon keeps a queue and one thread that runs it, in the order
given, under the same lock as direct changes. A job belongs to the
daemon, not to the connection that queued it: the client may leave, and
the job and those behind it still run to their end. Each job has its own
trace, changed under a lock, so `job` returns the steps done so far
while it runs; a step that has begun and not ended has the status
`incomplete`. A queued job can be cancelled; a running one cannot. The
last 64 finished jobs are kept in memory, and all are forgotten when
the daemon restarts.

The console sends every change as a job and reads it once a second, so
the workflow graph grows stage by stage; when the host stops answering,
the entry says so and keeps trying, and shows the outcome when the host
is back. With **Queue** on, changes are held in the browser and sent
together as one batch. Reads (lists, tables, dry runs, previews) stay
direct calls.

## What the console holds by subscription

Beside the pool of connections its requests take (over SCTP one
association every request shares), the console keeps one more
connection to each agent a page reads from, on a thread of its own
(`watch.c`), for RFC 8639's dynamic subscriptions over cblink's
SUBSCRIBE streams.  A topic is subscribed the first time a read of it
is asked, for the user it is asked for, whose access rules (NACM, RFC
8341) the agent holds the subscription to, and let go when no read
asked for it for two minutes.  A host's rules are its own: the console
puts its owners in the host's group admin only when an owner asks
(Settings, AAA, Roles: synchronize, `arcana-console:hosts/host=<id>/nacm-sync`)
and once when the host enrols, and touches nothing else of them:

| Topic | Subscription | Answers |
|-------|--------------|---------|
| jobs | arcana-jobs, on-change (the agent tells each job's change; RFC 8641) | `GET jobs`; a job's read while it is queued |
| stats | arcana-host's stats, periodic, 5 s | `GET stats` |
| jails | arcana-jails, periodic, 5 s | `GET jails` (the host by its hello, asked each time) |
| sdwan | arcana-sdwan, periodic, 2 s; arcana-probe read by the thread at that period, as the user | `GET sdwan?after=` (subscribed for those alone; the samples after a time held, ten minutes of them) |
| events | the NETCONF stream | every page following the host's events |

A push-update is the whole of a topic, a push-change-update a YANG
Patch applied to a copy of the last; each is made the module's struct
the read's JSON is built from, so a read answered from what is held has
the shape the host's own answer has, its trace saying how old it is.
The first read of a topic, a read a page asks with its steps shown, and
every read while nothing is held go to the host as before; a change the
console makes to a host, or a job's there, lets go of what is pushed
periodically until its next push, so a read after a change is never
answered with the state before it.  A running
job's trace is its read action's alone: the console reads it at most
once a second whatever number of pages poll it, and keeps a finished
job's read.  The connection lost, what is held goes with it; it is made
again one second on, doubling to a minute, and the topics still asked
for are subscribed anew.  An agent that has no such subscription (one
of the release before) refuses it, and its reads, and the pages that
follow its events, go to it as they did.  `GET
arcana-console:hosts/host=<id>/watch` says the connection's state, each topic's,
and how often the console went to the agents and answered without them.

## Services

The daemon never reads or writes `rc.conf` itself.  It lists the
executable scripts of `/etc/rc.d` and `/usr/local/etc/rc.d`, reads
`<name>_enable` from `sysrc -A` (which evaluates the configuration
without running any script; `service -e` runs every one, and scripts
with no default for their rcvar warn each time) and asks `service
<name> status` whether the enabled ones run, and changes things with `service <name> <verb>` and
`sysrc(8)`, so quoting, `rc.conf.d` and `rc.conf.local` mean what they
mean to the system.  A service's variables are those `sysrc -a` lists
whose names start with the script's name or its rcvar's stem; only such
names can be set, and nothing is passed through a shell.  Every program
run is a step in the trace with its output; listing a host with many
enabled services takes one `status` run per service, so the console
fetches the list only when the Services tab is opened or refreshed.
A script runs whatever it runs, as root: for a viewer's request none
is run, and the list's running state and a service's read are what
the agent last saw (its own look every five minutes, and every list
or read of an operator's, the admin's or the console's).

## Addresses and aliases

A live address change sets the running jail's `ip4.addr`/`ip6.addr` with
jail_setv(3) and, when the jail has an `interface` parameter, adds or
removes the alias with SIOCAIFADDR/SIOCDIFADDR, as ifconfig(8) would.
jail(8) only removes the aliases of configured addresses when a jail
stops, so arcana-agent removes the ones that were added live after a stop or
restart, and all of them after a kill, which bypasses jail(8).

A persistent change edits the jail's own block in the file that defines
it, keeping every other byte; values inherited from global statements or
`*` blocks are left alone.

## Jail states

`running`, `stopped`, `dying` and `absent` come from the host.  The UI
adds `starting`, `stopping` and `restarting` while an action is in
flight, `error` after a failed one, and `unknown` when data is stale or
the host is unreachable.

## Offline behaviour

The service worker precaches the application shell (HTML, CSS, the wasm
and its glue, fonts, icons) under a name derived from a checksum of the
shell; `/restconf/` and `/api/` are never cached, and nothing about
jails is kept in browser storage.  The top bar shows three signals: NET
(`navigator.onLine`), API (`/api/health`, every 15 s) and HOST (the last request to the selected
arcana-agent).  Jail data older than 30 s, or from a failed refresh, is
dimmed and marked stale with its age; jails of an unreachable host show
as unknown.  Started offline, the app says that it is there but jail data
is not, and reconnects by itself.

## Layout

```
cblink/                 the transport, a submodule
libwebpush/             Web Push encryption and VAPID, a submodule
jailconf/               jailconf(8) and libjailconf, in-place jail.conf editing, a submodule
share/arcana/           the kept structures, the jobs, the cluster's family
share/mk/               build settings shared by every Makefile
share/yang/             the YANG modules and their SIDs
lib/libvarconf/         in-place rc.conf, loader.conf, sysctl.conf editing
usr.sbin/arcana-agent/  arcana-agent(8)
usr.sbin/arcanactl/     arcanactl(8)
usr.sbin/arcana-enrol/  arcana-enrol(8)
www/arcana-console/     arcana-console(8)
www/arcana-ui/          the PWA
docs/                   this file, the other guides, restconf-modules.py
tests/                  the top of the installed test suite
```

Each directory has a `tests/` with atf-c or atf-sh tests; `make check`
runs them with kyua(1), and they install to `${TESTSBASE}/arcana`.
The submodules' suites (cblink's, jailconf's) are their repositories'.

| Suite | Kind | Covers |
|---|---|---|
| `arcana-agent` | atf-sh | listing through jail(8) -e, actions and address changes with a stand-in jail(8), traces, mutual TLS; as root, a real throwaway jail, live addresses and alias cleanup |
| `console` | atf-c | WebAuthn as an authenticator would do it (ES256, Ed25519, wrong origin, RP, challenge, signature, counter), CSRF, servers, jails through arcana-agent over a socket and over mutual TLS |
| `console/pwa` | atf-c | the PWA in Chromium with a virtual authenticator: enrolment, an action, the workflow and raw output, an address preview, login, offline reload |
