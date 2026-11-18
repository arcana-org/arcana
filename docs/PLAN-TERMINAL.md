# Plan: a terminal to each host from the panel

A host's Terminal tab opens a terminal on the host, or in one of its
running jails, in xterm.js. What runs on the terminal is the host's own
login(1), as getty(8) would run it on a line. The person types an
account's name and its password, and the host's own PAM
(`/etc/pam.d/login`) decides. The agent picks no user and runs no shell
of its own. Root logs in only as the host's policy allows (securetty,
PAM); there is no way around it. In a jail it is the jail's own login,
so the jail's accounts. The console decides only who may reach the
login prompt. A: the agent, C: the console, U: the page, T: tests, Y:
YANG, D: documents.

## Built (TERM-1)

**Y.** arcana-stream gets a sixth command, `terminal` (6), opened by
`jail=`, `rows=`, `cols=` and `from=`. Its chunk structure gets three
leaves: `rows` and `cols`, a window size the console sends, and
`login`, the account that logged in, which the host sends. The SIDs
are 85 969 to 85 971, in arcana-stream's own range (SIDS.md). No new
range was needed.

**A (ira/terminal.c).**
- A session is a pseudo-terminal from posix_openpt(2). Its slave end is
  the controlling terminal of a session of its own (setsid, TIOCSCTTY).
- login runs on it with `-h <from>`. In a jail, jexec(8) runs the
  jail's own login by the jail's number: a process that has had threads
  may not jail_attach(2) itself, but an exec'd one may.
- The child runs only async-signal-safe calls between fork and exec.
  It resets every signal (an ignored signal stays ignored across exec)
  and sets the system's umask.
- Each session has a thread of its own. It reads the terminal only as
  fast as the stream's credit lets it. With no credit it stops reading,
  the pty fills, and whatever writes to the terminal waits; the agent's
  loop never waits. Typed bytes are written without blocking, up to
  1 MB queued; more than that ends the session.
- A chunk with rows and cols is TIOCSWINSZ, which sends the foreground
  SIGWINCH.
- The stream's end hangs the session up: SIGHUP to the terminal's
  foreground group and to login's group, then the master is closed (the
  kernel's own hangup). After 5 s, SIGKILL goes to what is left of
  login's group, and login is reaped.
- The session's end (login gone, every slave closed) closes the stream
  with "the session ended".
- Limits: 8 sessions at once. A session nobody types in for
  `--terminal-idle` seconds (default 1800) is hung up.
- `--terminal-login` names the program, `/usr/bin/login` by default; a
  test sets a stand-in.
- For the host's sessions, the account that logged in is read from
  utmpx (USER_PROCESS, login's pid, the pts line) every 2 s for the
  first 10 minutes, then sent once. A jail's utmpx is the jail's and is
  not read: nothing is guessed.
- Each open, login and end goes to syslog, with the bytes each way.

**A (admit.c).**
- The op's flags are STREAM, AUTH and NACM, without DENY. The password
  is the host's to judge, and NACM's exec-default lets the op through.
- A host whose exec-default is deny (Settings, nacm_exec_default)
  gives terminals to its group admin alone, unless its admin adds a
  rule permitting `arcana-stream:terminal` by hand (TERM-3 does not
  widen it).

**C (terminal.c).**
- `/api/terminal` is a WebSocket. The page's first message is
  `{"server", "jail", "rows", "cols"}`. After that, binary messages are
  bytes each way, and `{"resize": [r, c]}` is a new size. The console
  answers with `{"opened"}`, `{"login"}`, `{"end"}` or `{"error"}`.
- Who may open one:
  - A user signed in with a security key. cnodes.c gives this path no
    API token, and no session opened by a password the console limits.
  - Whose role on that host is operator or admin: principal_may()
    against ROLE_OPERATOR, so owners get every host and a tenant's users
    get their tenant's hosts.
  - A viewer never.
  - Only our page may ask, judged by its Origin, as for `/api/stream`.
  - The socket is bound to its session (sbind). The session and the
    role are judged again every second. If either is gone, the session
    is hung up.
- The audit trail (audit.c, HMAC-chained) records:
  - `terminal-refused` (Block), with who, the host and jail, and from
    where;
  - `terminal-opened` (Allow), with who, the host (name and id) and
    jail, and from where;
  - `terminal-closed`, with the bytes typed and written, the seconds,
    the account that logged in when the host told it ("not told"
    otherwise), and why it ended.
- Each terminal is a task acting for its user, so NACM holds the stream
  to that user, on the shared connection to the host. Output is taken
  from a 256 KB manual-credit window. The window is given back only
  while the page's socket has less than 256 KB queued (ws_queued()), so
  a slow page holds back only its own terminal.
- Limits: 4 terminals per user and 32 per console. Typed bytes waiting
  for the host are capped at 64 KB.

**U (term.c, bridge.js arcTerm).**
- The tab has a picker of the host and its running jails, Connect and
  Disconnect, and an element the page leaves alone (`data-keep`). The
  element is named by the host, so another host's tab is a different
  element and the previous terminal is hung up.
- xterm.js 5.5.0 and addon-fit 0.10.0 are vendored in `vendor/xterm`
  (MIT; versions and sha512 recorded in vendor/README). They are served
  as shell files and cached by the service worker, never fetched from a
  CDN.
- The colours come from the theme's tokens and change with the theme.
  The terminal is fitted when its box changes size, and the new size is
  sent to the host.
- A status line shows "connecting", "connected on pts/N", "logged in
  as", "ended: why", "refused" or "the connection dropped", with
  Connect to start again. Leaving the tab hangs up.

**T.**
- agent_test `terminal_session`: the stand-in login with `-h`; a name
  and password; `echo` through the pty; `stty size` as opened and after
  a resize; the shell gone after the stream ends; a wrong password and
  `exit` each ending the stream; the opening's checks.
- agent_test `terminal_limits`: eight sessions, the ninth refused, a
  place freed when one goes; the idle hang-up.
- agent_test `terminal_jail`: a fake jail through the fake jexec.
- console_test `terminal_socket`: the owner's session end to end with
  37 bytes typed in the trail; a jail's; another Origin and no session
  refused; a viewer refused and that refusal in the trail; an operator
  allowed; an unknown host.
- pwa_test `pwa_terminal`: Connect; login in xterm.js; echo; a smaller
  terminal and `stty size`; Disconnect; the trail's rows; leaving the
  tab.

## Built (TERM-3) NACM's op rule

oprules.h's rules may now be protocol-operation rules: a rule with an
`rpc` (`rule-type` protocol-operation, `rpc-name`) and no path. Two
are added, `terminal` and `terminal-as` in module arcana-stream, both
exec permits for group operator. The agent's default rules (ynacm.c,
exec-default permit) carry them. The console's nacm-sync (ytrans.c,
op_list(deny), op_list_whole(deny)) synchronizes them only to a host
whose exec-default is permit, where operators had the plain terminal
already: nothing is widened. On a host whose exec-default is deny the
operator rule-list is made without them (and made anew if it has
them), so its operators have no terminal and no mapped login; an admin
who wants them adds a rule by hand, in a rule-list of its own (the
console remakes its own rule-list whole). The Settings text of
nacm_exec_default and the Terminal tab say so. ynacmw -c passes an
operation's rule, which has no path to compile. console_test
`terminal_nacm_deny`.

## Built (TERM-6) Mapped logins

A console user mapped to a local account of a host gets that
account's login on the host's terminal without typing a password.
Designed after an independent review, whose required changes are the
points below.

**Who asks, and for whom (A, admit.c, ira/terminal.c).**
- A command of its own, `terminal-as` (7), flagged STREAM, AUTH, NACM
  and DENY (STREAM_OPF): nacm:default-deny-all, so NACM refuses it
  unless a rule permits it (group admin's permit-all, group operator's
  `terminal-as` rule from TERM-3). The plain `terminal` op is as it
  was.
- The console user is `cbl_req_user(req)`, the very name NACM judged;
  never a second field. There is no ticket, signature, nonce or replay
  cache: a signature would add nothing, since whoever holds the console
  already holds every host as root (signed agent updates, the
  authorized_keys ssh.c writes).
- Only PEER_CONSOLE, PEER_GROUP or PEER_ROOT may ask. PEER_LOCAL is
  refused, as is a request for no user (the recovery session naming
  none) and one for the user `console` unless it is root's on the
  socket (term_open()).

**The host is the authority (term_allowed()).**
- `/usr/local/etc/arcana/terminal-users` (`--terminal-users`): lines
  of `scope account [+root] console-user ...`, scope `host` or
  `jail:<name>`, `#` comments, a CR before LF dropped. Absent: the
  feature is off ("mapped logins are off on this host", EPERM: never
  EOPNOTSUPP, which is cblink's unknown command). Opened as sshd's
  secure_filename(): every directory from / down by the descriptor of
  the one above (openat, O_NOFOLLOW, fstat), each root's (or the
  agent's own user's) and writable by no one else (a sticky directory
  of root's, /tmp, only for an agent that is not root: the tests'; as
  root, never); no symbolic link on the way or as the file;
  the file regular, root's, mode 0600 or stricter, 64 KB at most
  (term_users_open(), secure_node()). Otherwise it is refused whole, as
  is a line that is not one or of more than 64 words. A word beginning
  with `+` is a flag, never a console user; `+root` is the only one and
  another refuses the file.
  No group allowlist.
- It is judged again while a mapped session lasts: every 2 s
  term_run() walks its whole way again (term_users_open()), and reads
  its words again when it changed (device, inode, size, times, mode,
  owner) (term_still()); a directory loosened, a file gone, one it no
  longer allows, or
  an uid-0 account whose line lost `+root`, is hung up ("the host's
  terminal-users no longer allows it").
- No job, sysfile entry, bundle or YANG node writes it: the sysfile
  table (sysfiles.c) has no entry for it, bundle.c carries only
  history.conf, ipfw.rules, config.mk and sdwan-* of the agent's
  directory, and no module names it (agent_test config_bundle and
  terminal_mapped_scope).
- The console's mapping only chooses among what the file allows.
- Scope is explicit: a host line never applies to a jail nor a jail
  line to the host.
- Root by uid: on the host getpwnam_r(3), pw_uid 0 (root, toor, any
  alias) refused unless the line says `+root`. In a jail the account
  is matched by name against the file's `jail:` lines alone, and the
  jail's getent's uid 0 needs `+root` too.
- `--terminal-users none` turns the feature off: `terminal-as` is
  refused with EPERM, "mapped logins are off on this host", never the
  unknown command an older agent answers. The tests emulate such an
  agent by `--test-unregister terminal-as` (for the tests alone: the
  operation left unregistered).

**The account (account_ok(), host_account(), jail_account()).**
- `[a-z_][a-z0-9_-]{0,31}` on both sides (agent and console), so never
  a leading `-`.
- argv: `login -f -h <address> -- <account>`, in a jail after
  `jexec <jid>`. `-h` stays the address from_ok() checks (from= is
  required); the console user goes to syslog and the audit, not into
  `-h`.
- `login -f` of an account that does not exist falls back to the
  prompt, and `-f` never calls pam_acct_mgmt(3). On the host, before
  the fork, in the session's thread: the account exists; not
  `*LOCKED*`; not past pw_expire; its password not past pw_change
  ("password expired"); its shell not nologin(8) or false(1);
  `/var/run/nologin` (the class's
  `nologin`, `--terminal-nologin` for a test's stand-in) absent unless
  the class has `ignorenologin` or the account is uid 0 (as
  pam_nologin(8) lets root; `+root` is still asked); the class's
  auth_timeok, auth_hostok and auth_ttyok. login.access(5) and
  securetty are not consulted on this path: the file stands for them.
- After the fork the host's session is established only once
  term_login() (utmpx) reports exactly the requested account; until
  then typed bytes are held, not written to the terminal. Another
  account is hung up ("login(1) logged in X, not Y"), none within 10 s
  too.
- A jail: a pre-flight `jexec <jid> getent passwd <account>`
  (`--terminal-getent`, 5 s at most) proves the account there: not
  `*LOCKED*`, uid 0 only by `+root`, its shell. The jail's utmpx is not
  read (the jail controls that file), so a jail's mapped login is never
  audited as confirmed. What is typed waits until login wrote anything.
  The residual: an account gone from the jail between its getent and
  login -f gets the jail's login prompt, which is output, so typing
  reaches it; the jail's own password then decides.
- Nothing that may wait runs on the connection's I/O thread: the
  stream of a mapped login is accepted first (its opened JSON names the
  tty, account and scope, no pid); the account's checks (the host's
  getpwnam_r and login class, the jail's getent) and login's fork are
  the session's own thread's (term_run(), term_spawn()), and a
  refusal there closes the stream with its errno and why. The hangup's
  reaping is that thread's too; the I/O thread's own failure paths kill
  at once (term_kill(): SIGKILL, reaped as it dies). The empty-password
  look runs at the start and every 10 minutes in a thread of its own,
  not per open.
- Refusals keep their errno (EPERM, ENOENT, EACCES...). What a request
  said is logged to LOG_AUTH only once validated (else "not given or
  not a name"), and the scope is spelt `host` or `jail:<name>`
  everywhere.

**The console (servers.c, terminal.c).**
- arcana-console's host gains `terminal-prompt` (allowed, never) and
  the list `terminal-login` keyed by jail (`.` the host) and user,
  with the account, and its author and time (config false). Kept in
  servers.json by the user's id, so a user removed and another made
  with the name has none, and keyed by (host id, jail or none, user
  id): no tenant-wide default reaches jails. SIDs 96 000 to 96 006.
- Changing it changes the host's entry: its admins' alone (403 to an
  operator), from a security key's session alone (session_by_key():
  not a password's, not an API token's; 403), as a terminal is opened,
  and with If-Match, the hosts' entity-tag as read (428 without it, 412
  when stale): servers.c term_change_why(). A host added with either by
  someone who is not its admin, or not by a key, is refused (403). A
  name that is no user's gets one answer, so no tenant's admin learns
  which users the console has. Each mapping added, changed or removed is a
  `terminal-mapping` row (Administer) with who and when; the switch
  turned either way a `terminal-prompt` row.
- The page writes a mapping by its own path
  (`hosts/host=<id>/terminal-login=<jail>,<user>`, PUT and DELETE) and
  the switch by its leaf (`.../terminal-prompt`), never the host's
  whole entry: a stale tab brings nothing back (its If-Match, the
  host's ETag it read, refuses the stale write; the tab reads the host
  again either way). The page's other host forms write their own nodes
  too, each in one request: the alerts' mutes, the rollback timer and
  the address each by one YANG Patch of the host's entry (host_edit(),
  host_yang_patch(): remove edits, which mind no absence, and merges;
  all of it or none, one If-Match), the pkg repositories by their list
  entry (host_leaf()); a failure re-reads the host, so the form shows
  what the console has. The page has no whole-entry write left.
- On a console cluster, servers_reload() (servers.json written by
  another node) does not bump the hosts' entity-tag, so the 412 guard
  does not see another node's change; the page writes per node, so only
  a third party's whole-entry writer is exposed to it.
- `/api/terminal`: the user's mapping for that host and jail opens
  `terminal-as`, unless the first message says `"prompt": true` and
  the host allows the prompt. With `terminal-prompt` never and no
  mapping, refused (`terminal-refused`).
- tsock_ok(), every second, also checks the mapping: removed or
  changed, the terminal is hung up ("the mapped login was removed or
  changed"); a plain terminal is hung up when the prompt is turned off.
- An agent without `terminal-as` (EOPNOTSUPP, "unknown command"):
  "this host's agent cannot do mapped logins: update it"; never the
  prompt in its place. Any other failure says its own reason.
- A mapped login's terminal-opened is written once the host writes or
  tells the login (a session that writes nothing, .hushlogin or an
  empty prompt, is opened by its login); closed before either, it is a
  terminal-refused with the host's reason. A synchronous ys_open
  failure is a terminal-refused too.
- The trail: terminal-opened says the account requested; a
  `terminal-confirmed` row when the host tells the login (Allow when
  it is the account, Block otherwise); terminal-closed `X requested,
  confirmed` or `not confirmed`; a refusal of the host's is a
  terminal-refused with its reason.
- A host's peer name may be NULL; cblink then checks the certificate
  against the URI's host (cbl_tls.c set_peer_name()), never the CA
  alone, and an empty one is never stored (dup_or_null()).

**The agent's logs.** LOG_AUTH notice for each open, confirmation,
refusal and end: the console user, the account, the scope, the pts and
the address.

**Finding.** Accounts with an empty password are one fault,
`empty-password` (Major) on `accounts`, an arcana-alarms identity
(SID 96 020): "N accounts log in with no password; see the host's auth
log". It names none, since every alarm reader, mail and Telegram see
it; the names go to LOG_AUTH alone, when they change. Looked for at
the start and every 10 minutes (terminal_findings_start()).

**U (term.c, bridge.js).** Before Connect the tab says "You will be
logged in as <account>" (or that the host allows no prompt and no
mapping is there, Connect disabled); "The password prompt instead"
where the host allows it. The status says "logging in as", then
"(confirmed by the host)". The host's admins see "Mapped logins": the
switch, the table (sorted and filtered), Remove, and a form to map,
under a warning that a mapping grants that account's full rights,
sudo and wheel included.

**T.**
- agent_test `terminal_mapped`: login -f's argv; typed bytes after
  utmpx; a leading `-` and other non-names; no from=; an unknown
  account; toor (uid 0) without and with `+root`; expired; locked;
  nologin shell; a user the file does not name; NACM's refusal of a
  user in no group (the plain terminal still given); the recovery
  session naming no user; another account logged in and none at all
  hung up; the LOG_AUTH lines; account= twice; unvalidated text not
  logged; nologin(5) by a stand-in; `+root` never a user; the file
  emptied under a session hangs it up; the empty-password fault without
  names.
- agent_test `terminal_mapped_scope`: a host line not a jail's and a
  jail line not the host's; the jail's getent (no account, nologin
  shell, uid 0 without `+root`, locked, each closing an accepted
  stream; then login -f by jexec, never confirmed); a getent that
  sleeps holds up no other request; the file 0640, a world-writable
  directory on its way, a symbolic link, a malformed line and an
  unknown flag refused, absent off; no sysfile writes it;
  `--terminal-users none` gives "unknown command".
- agent_test `terminal_mapped_local`: PEER_LOCAL refused though NACM
  and the file would let its user (libfakejail's FAKEPEERUID).
- agent_test `config_bundle`: no bundle carries the file.
- libfakejail stands in for the accounts (FAKEPASSWD), the peer's uid
  (FAKEPEERUID) and utmpx (FAKEUTX): no real account is touched.
- console_test `terminal_mapped`: a console operator adding a host
  with a mapping or the switch refused; a host operator may not map; a
  non-name refused; the owner's mapping by its path and its trail row;
  login -f confirmed, the terminal-confirmed row, echo; the mapping
  changed and removed mid-session each hang up; a host refusal in the
  trail; "prompt": true with allowed (the prompt) and never (mapped);
  the switch by its leaf, audited both ways; an old agent.
- console_test `terminal_nacm_deny`: TERM-3 not widened.
- pwa_test `pwa_terminal_mapped`: mapped by the form, "you will be
  logged in as" before Connect, a stale tab's switch bringing back no
  mapping removed behind it, no way in left.

## Left

### TERM-2 A real login in a vnet jail (T)

A root case in agent_root_test.sh, in the VM round only:
- a vnet jail rooted in a directory of its own (never `path=/`), with
  the base read-only by nullfs;
- an `/etc` of its own with one test account (pwd_mkdb -d) and the
  host's pam.d;
- a session logged in by the real login, utmpx's `login` seen, and a
  wrong password refused.

It was not written blind. Root suites are not run on production hosts,
and the case needs the VM to be built against.

### TERM-3 NACM's op rule (A, C)

Built: see above.

### TERM-4 arcanactl terminal (A)

The same stream from arcanactl: raw mode on its own tty, SIGWINCH as
resize. This is for the console host's admin when the page is down.

### TERM-5 The book (D)

A page on the Terminal tab in arcana-docs: what it runs, who may open
it, the trail's rows, the limits, and the FreeBSD facilities behind it
(pts(4), login(1), PAM, jexec(8), utmpx(5)).
