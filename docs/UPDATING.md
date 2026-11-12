# Updating Arcana

The console asks GitHub's release feed every six hours and shows a
banner when a newer version is out; `update_check = false` in `web.conf`
turns that off. It does not replace itself, since it runs unprivileged:

- the container image carries `io.containers.autoupdate=registry`, so
  `podman auto-update` (from cron, say) pulls a newer `ghcr.io/spmzt/arcana`
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
there clones the repository, builds all of Arcana as `nobody`, runs
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
agent_source = "https://github.com/spmzt/arcana.git";
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
  readable by `nobody`, whom git runs as.

From a shell, `arcanactl agent-build -y` confirms the keys shown, and
`-i key` names the key.

The host that builds needs what the build needs: `git`, the base
compiler, `devel/libcbor` and `net/libyang3` (for cblink-gen, which
reads the wire's YANG modules); cblink is cloned with the tree, a
submodule, and built with it. If the linker or a library is somewhere
else on it, `/usr/local/etc/arcana/config.mk` there is copied into the
tree as its `config.mk`. When the agent is root, git and make run as
`nobody`. From a shell, `arcanactl agent-build [-o file] repository
[ref]` builds and saves the program.

## Versions

The agent and the console have versions of their own, and every change
to one bumps it: `ARCANA_AGENT_VERSION` in
`usr.sbin/arcana-agent/agent.h`, `ARCW_VERSION` in
`www/arcana-console/console.h`. A host's header and the tree show the
agent's; the update dialog shows the one the console would send.
