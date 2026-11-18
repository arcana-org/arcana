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
  gives terminals to its group admin alone, unless a rule permits
  `arcana-stream:terminal`. TERM-3 covers the rest.

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

oprules.h has data-node rules only. A protocol-operation rule
(`rpc-name terminal`, module arcana-stream) for group operator, kept
alike by the agent's defaults and the console's nacm-sync, would give
operators terminals on hosts whose exec-default is deny.

### TERM-4 arcanactl terminal (A)

The same stream from arcanactl: raw mode on its own tty, SIGWINCH as
resize. This is for the console host's admin when the page is down.

### TERM-5 The book (D)

A page on the Terminal tab in arcana-docs: what it runs, who may open
it, the trail's rows, the limits, and the FreeBSD facilities behind it
(pts(4), login(1), PAM, jexec(8), utmpx(5)).
