#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
#
# arcana-agent(8) as root, on a throwaway jail it defines itself:
# "arct_CASE", path "/", no mounts, exec hooks that only echo, and
# addresses on lo0 in a /24 of 127.0.0.0/8 of the case's own.  Each case
# removes the jail and its addresses when it is done, and refuses to run
# if a jail of that name already exists.
#
# The cases run side by side (kyua's parallelism): each names its jails,
# interfaces and addresses for itself.  Those marked is.exclusive change
# what the whole host shares: FIB 0's routes, the host's ipfw, a commit
# of the host's interfaces or routes as read a moment before; or measure
# times another case's load would change.
#

# The case run: the script's last argument, NAME or NAME:cleanup.
for _arg; do
	_case=${_arg%:cleanup}
done
JAIL=arct_${_case:-test}
YJAIL=arcy_${_case:-test}
# The jail's addresses on lo0, the third octet the case's.
case "${_case:-}" in
lifecycle)		JNET=127.0.10 ;;
live_address)		JNET=127.0.11 ;;
aliases)		JNET=127.0.12 ;;
yang_jail_actions)	JNET=127.0.13 ;;
*)			JNET=127.0.14 ;;
esac

# Does the kernel have SCTP: compiled in (kern.features.sctp) or the
# module loaded.
has_sctp()
{
	[ "$(sysctl -n kern.features.sctp 2>/dev/null)" = 1 ] ||
	    kldstat -q -m sctp 2>/dev/null
}

# A new epair(4), the name of its a end: the cloner's next unit, else
# one of its own.  The cloner's units are counted per vnet while the
# names are checked against what is there: in a vnet jail given an
# epair's b end, "ifconfig epair create" fails (EEXIST) for good once
# the count reaches that unit.
epair_create()
{
	local e n

	e=$(ifconfig epair create 2>/dev/null) && { echo "$e"; return 0; }
	for n in $(seq 100 199); do
		e=$(ifconfig "epair$n" create 2>/dev/null) &&
		    { echo "$e"; return 0; }
	done
	echo "agent_root_test: no epair could be made" >&2
	return 1
}

programs()
{
	JGD="$(atf_get_srcdir)/../arcana-agent"
	[ -f "$JGD" -a -x "$JGD" ] ||
	    JGD=$(atf_config_get arcana-agent /usr/local/sbin/arcana-agent)
	JGC="$(atf_get_srcdir)/../../arcanactl/arcanactl"
	[ -f "$JGC" -a -x "$JGC" ] ||
	    JGC=$(atf_config_get arcanactl /usr/local/sbin/arcanactl)
}

start_daemon()
{
	local i

	if jls -j "$JAIL" >/dev/null 2>&1; then
		atf_skip "a jail named $JAIL already exists"
	fi
	programs
	mkdir etc etc/jail.conf.d
	cat > etc/jail.conf <<EOF2
$JAIL {
	path = "/";
	host.hostname = "$JAIL.local";
	interface = lo0;
	ip4.addr = $JNET.1;
	persist;
	exec.start = "/bin/echo $JAIL: exec.start ran";
	exec.stop = "/bin/echo $JAIL: exec.stop ran";
}
EOF2
	SOCK="unix:$(pwd)/s.sock"
	# What it keeps (probes, rules, faults) in the work directory, not
	# the host's /usr/local/etc/arcana, where the next case would find it.
	"$JGD" -F -l "$SOCK" -f "$(pwd)/etc/jail.conf" \
	    -D "$(pwd)/etc/jail.conf.d" -1 "$(pwd)/history.conf" \
	    --nacm "$(pwd)/nacm.cbor" ${DAEMON_ARGS:-} > daemon.out 2>&1 &
	echo $! > daemon.pid
	for i in $(seq 1 100); do
		grep -q 'ready' daemon.out 2>/dev/null && return
		sleep 0.05
	done
	atf_fail "arcana-agent did not start: $(cat daemon.out)"
}

# Whatever happened, leave no jail, address or daemon behind.
cleanup()
{
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	[ -f etc/jail.conf ] && jail -f etc/jail.conf -r "$JAIL" >/dev/null 2>&1
	for a in $JNET.1 $JNET.2 $JNET.3; do
		ifconfig lo0 inet "$a" -alias 2>/dev/null
	done
	true
}

lo0_has()
{
	ifconfig lo0 inet | grep -q "inet $1 "
}

# Waits up to ten seconds for a shell condition: an unconfirmed commit
# undone at its timeout.  The checks after it say what did not happen.
wait_for()
{
	local i

	for i in $(seq 1 100); do
		sh -c "$1" >/dev/null 2>&1 && return
		sleep 0.1
	done
}

atf_test_case lifecycle cleanup
lifecycle_head()
{
	atf_set "descr" "start, restart, stop and kill a real jail"
	atf_set "require.user" "root"
}
lifecycle_body()
{
	start_daemon
	atf_check -o save:start.out "$JGC" -t -c "$SOCK" start "$JAIL"
	atf_check -o match:'^State: running \(jid [0-9]+\)$' cat start.out
	atf_check -o match:"\\| $JAIL: exec.start ran" cat start.out
	atf_check -o ignore jls -j "$JAIL"
	lo0_has $JNET.1 || atf_fail "jail(8) did not add $JNET.1"
	atf_check -o match:"^$JAIL +running +[0-9]+ +$JNET.1 " \
	    "$JGC" -c "$SOCK" list
	atf_check -s exit:1 -o ignore -e match:'already running' \
	    "$JGC" -c "$SOCK" start "$JAIL"

	atf_check -o save:restart.out "$JGC" -t -c "$SOCK" restart "$JAIL"
	atf_check -o match:"jail -f .* -rc $JAIL: exit status 0" \
	    -o match:'exec.stop ran' -o match:'exec.start ran' cat restart.out

	atf_check -o match:'^State: stopped$' "$JGC" -c "$SOCK" stop "$JAIL"
	atf_check -s exit:1 -o ignore -e ignore jls -j "$JAIL"
	lo0_has $JNET.1 && atf_fail "$JNET.1 left on lo0"

	atf_check -o ignore "$JGC" -c "$SOCK" start "$JAIL"
	atf_check -o save:kill.out "$JGC" -t -c "$SOCK" kill "$JAIL"
	atf_check -o match:'\[syscall\] jail_remove\(2\)' cat kill.out
	atf_check -s exit:1 sh -c "grep '\[exec\]' kill.out | grep -v ' -e ' | \
	    grep -v 'sysrc -i -n jail_'"
	# Each coming and going was an event as it happened (EVFILT_JAIL).
	sleep 0.5
	atf_check -o save:ev.json "$JGC" -c "$SOCK" events
	atf_check -o match:"\"kind\":\"jail-state\",\"data\":\\{\"jail\":\"$JAIL\",\"state\":\"running\",\"jid\":[0-9]+\\}" \
	    -o match:"\"kind\":\"jail-state\",\"data\":\\{\"jail\":\"$JAIL\",\"state\":\"stopped\"" \
	    cat ev.json
	# Four starts (start, restart, start again) and as many ends, of
	# this jail: other cases' come and go meanwhile.
	atf_check -o inline:'3\n' sh -c "grep -o '\"jail\":\"$JAIL\",\"state\":\"running\"' ev.json | wc -l | tr -d ' '"
	atf_check -o inline:'3\n' sh -c "grep -o '\"jail\":\"$JAIL\",\"state\":\"stopped\"' ev.json | wc -l | tr -d ' '"
}
lifecycle_cleanup()
{
	cleanup
}

atf_test_case jail_events_nested cleanup
jail_events_nested_head()
{
	atf_set "descr" "a jail made inside another, an LNE in an LNE, is an" \
	    "event when made and when removed (EVFILT_JAIL)"
	atf_set "require.user" "root"
}
# The jail the nested events are made in, its own name.
NJAIL=arcana-nested

jail_events_nested_body()
{
	start_daemon
	jls -j "$NJAIL" >/dev/null 2>&1 && atf_skip "a jail named $NJAIL exists"
	atf_check -o ignore jail -c name="$NJAIL" path=/ vnet persist \
	    children.max=1
	atf_check -o ignore jexec "$NJAIL" jail -c name=inner path=/ persist
	atf_check -o ignore jls -j "$NJAIL.inner"
	atf_check -o ignore jexec "$NJAIL" jail -r inner
	atf_check -o ignore jail -r "$NJAIL"
	sleep 0.5
	atf_check -o save:ev.json "$JGC" -c "$SOCK" events
	for j in "$NJAIL" "$NJAIL.inner"; do
		for st in running stopped; do
			atf_check -o inline:"$j $st 1\n" sh -c "echo $j $st \$(grep -o '\"jail\":\"$j\",\"state\":\"$st\"' ev.json | wc -l | tr -d ' ')"
		done
	done
}
jail_events_nested_cleanup()
{
	jail -r "$NJAIL" >/dev/null 2>&1
	cleanup
}

atf_test_case jail_allow_live cleanup
jail_allow_live_head()
{
	atf_set "descr" "jail-allow on a running jail: a parameter set with JAIL_UPDATE as jail -m does, read back by jls and in the list; in safe mode and not confirmed, set back as it was"
	atf_set "require.user" "root"
}
jail_allow_live_body()
{
	DAEMON_ARGS="-w 2"
	start_daemon
	AJ=arcana-allow-test
	jls -j "$AJ" >/dev/null 2>&1 && atf_skip "a jail named $AJ exists"
	# In a jail, a child has only what its parent has: raw sockets,
	# and the second parameter one the parent is allowed.
	P2=allow.sysvipc
	if [ "$(sysctl -n security.jail.jailed)" = 1 ]; then
		[ "$(sysctl -n security.jail.allow_raw_sockets)" = 1 ] ||
		    atf_skip "this jail has no allow.raw_sockets to give its own"
		P2=
		for p in sysvipc mlock chflags; do
			if [ "$(sysctl -n security.jail.${p}_allowed)" = 1 ]; then
				P2=allow.$p
				break
			fi
		done
		[ -n "$P2" ] || atf_skip "this jail has none of allow.sysvipc, allow.mlock, allow.chflags to give its own"
	fi
	atf_check -o ignore jail -c name="$AJ" path=/ persist allow.raw_sockets=0
	atf_check -o match:'jailparam_set\(3\)' -o match:'JAIL_UPDATE, 2 parameters' "$JGC" -t -c "$SOCK" allow "$AJ" allow.raw_sockets=1 $P2=1
	atf_check -o match:'^(1|true)$' jls -j "$AJ" allow.raw_sockets
	atf_check -o match:'^(1|true)$' jls -j "$AJ" $P2
	# Safe mode: set to 0 and not confirmed, back to 1.
	atf_check -o match:'queued' "$JGC" -q -s -c "$SOCK" allow "$AJ" allow.raw_sockets=0
	sleep 0.5
	atf_check -o match:'^(0|false)$' jls -j "$AJ" allow.raw_sockets
	for i in $(seq 1 200); do
		"$JGC" -c "$SOCK" jobs | grep -q 'unconfirmed\|queued\|running' ||
		    break
		sleep 0.1
	done
	atf_check -s exit:1 -o match:'not confirmed within 2 s: undone' -o match:'undo' "$JGC" -c "$SOCK" job $("$JGC" -c "$SOCK" jobs | awk '$1 ~ /^[0-9]+$/ {print $1}' | sort -n | tail -1)
	atf_check -o match:'^(1|true)$' jls -j "$AJ" allow.raw_sockets
	atf_check -o ignore jail -r "$AJ"
}
jail_allow_live_cleanup()
{
	jail -r arcana-allow-test >/dev/null 2>&1
	cleanup
}

atf_test_case jail_base_chflags cleanup
jail_base_chflags_head()
{
	atf_set "descr" "A jail's base to pkgbase refused before anything changes where the running jail may not set files' flags (allow.chflags=0), said by allow.chflags"
	atf_set "require.user" "root"
}
jail_base_chflags_body()
{
	CJ=arcana-chflags-test
	jls -d -j "$CJ" >/dev/null 2>&1 && atf_skip "a jail named $CJ exists"
	mkdir -p r/etc r/usr/local/etc
	atf_check -o ignore jail -c name="$CJ" path="$(pwd)/r" persist \
	    allow.chflags=0
	start_daemon
	atf_check -s exit:1 -o match:"jail $CJ may not change files. flags \(allow.chflags=0\)" \
	    "$JGC" -c "$SOCK" jail-base "$CJ" convert
	# Nothing of the conversion's: no repository, no /etc kept aside.
	atf_check test ! -e r/usr/local/etc/pkg/repos/arcana-base.conf
	atf_check test ! -e r/var/backups/etc-before-pkgbase.tar
}
jail_base_chflags_cleanup()
{
	jail -r arcana-chflags-test >/dev/null 2>&1
	cleanup
}

atf_test_case config_files_not_at_boot cleanup
config_files_not_at_boot_head()
{
	atf_set "descr" "Arcana's rc.conf file on a filesystem of its own (/usr/local a dataset), which /etc/rc reads before it is mounted at boot: said in the state, and a commit into it refused with rc-conf-not-at-boot; the switch to the system's files still offered"
	atf_set "require.user" "root"
	# It mounts a filesystem: the host's mounts, which others read.
	atf_set "is.exclusive" "true"
}
config_files_not_at_boot_body()
{
	mkdir -p root/etc/defaults root/usr/local
	cp /etc/defaults/rc.conf root/etc/defaults/
	printf 'ntpd_enable="NO"\n' > root/etc/rc.conf
	mount -t tmpfs tmpfs root/usr/local 2>/dev/null ||
	    atf_skip "no tmpfs can be mounted here"
	mkdir -p root/usr/local/etc
	DAEMON_ARGS="--root $(pwd)/root"
	start_daemon
	atf_check -o match:'"arcana-at-boot":false' -o match:'"mode":"arcana"' \
	    "$JGC" -c "$SOCK" get agent
	atf_check -s exit:1 -e match:'mounts after it reads rc.conf at boot' \
	    "$JGC" -c "$SOCK" service -a rc-conf-files ntpd enable
	atf_check test ! -e root/usr/local/etc/rc.conf.d/arcana
	atf_check -o inline:'ntpd_enable="NO"\n' cat root/etc/rc.conf
	# The way out stays open: the switch to the system's files.
	atf_check -o match:'"to":"system"' "$JGC" -c "$SOCK" action \
	    agent/config-files switch to=system dry-run=true
}
config_files_not_at_boot_cleanup()
{
	cleanup
	umount -f "$(pwd)/root/usr/local" >/dev/null 2>&1
	true
}

atf_test_case jail_dying_namesake cleanup
jail_dying_namesake_head()
{
	atf_set "descr" "A jail removed but dying (a mount made inside holds it) and one made again of its name: one entry, the live one, the dying one in its dying list by jid"
	atf_set "require.user" "root"
}
jail_dying_namesake_body()
{
	DJ=arcana-dying-test
	jls -d -j "$DJ" >/dev/null 2>&1 && atf_skip "a jail named $DJ exists"
	if [ "$(sysctl -n security.jail.jailed)" = 1 ]; then
		[ "$(sysctl -n security.jail.mount_allowed)" = 1 ] &&
		    [ "$(sysctl -n security.jail.mount_tmpfs_allowed)" = 1 ] ||
		    atf_skip "this jail may not let its own mount a tmpfs"
	fi
	mkdir m
	atf_check -o ignore jail -c name="$DJ" path=/ persist allow.mount \
	    allow.mount.tmpfs enforce_statfs=1
	old=$(jls -j "$DJ" jid)
	# Mounted from inside: it holds the jail dying once removed.
	atf_check jexec "$DJ" mount -t tmpfs tmpfs "$(pwd)/m"
	atf_check -o ignore jail -r "$DJ"
	atf_check -o match:'^(1|true)$' jls -d -j "$old" dying
	atf_check -o ignore jail -c name="$DJ" path=/ persist
	new=$(jls -j "$DJ" jid)
	DAEMON_ARGS="-w 2"
	start_daemon
	atf_check -o save:j.json "$JGC" -c "$SOCK" get jails
	# Once: the live one, the dying one under it.
	atf_check -o inline:'1\n' sh -c "grep -o '\"name\":\"$DJ\"' j.json | wc -l | tr -d ' '"
	atf_check -o match:"\"dying\":\\[\\{\"jid\":$old,\"path\":\"/\"\\}\\]" \
	    -o match:"\"jid\":$new" cat j.json
}
jail_dying_namesake_cleanup()
{
	jail -r arcana-dying-test >/dev/null 2>&1
	umount -f "$(pwd)/m" >/dev/null 2>&1
	cleanup
}

atf_test_case live_address cleanup
live_address_head()
{
	atf_set "descr" "Live address changes use jail_setv(3) and ioctls only"
	atf_set "require.user" "root"
}
live_address_body()
{
	start_daemon
	cp etc/jail.conf before
	atf_check -o ignore "$JGC" -c "$SOCK" start "$JAIL"
	atf_check -o save:add.out "$JGC" -t -c "$SOCK" address add -l "$JAIL" \
	    $JNET.2
	atf_check -o match:"^IPv4: $JNET.1,$JNET.2\$" \
	    -o match:'\[syscall\] ioctl\(SIOCAIFADDR\)' \
	    -o match:'\[lib\] jailparam_set\(3\)' cat add.out
	# Only jail(8) -e, reading the configuration, runs a program, and
	# sysrc(8) reading what starts at boot (the jail's record).
	atf_check -s exit:1 sh -c "grep '\[exec\]' add.out | grep -v ' -e ' | \
	    grep -v 'sysrc -i -n jail_'"
	lo0_has $JNET.2 || atf_fail "alias not added"
	atf_check -o inline:"$JNET.1,$JNET.2\n" \
	    jls -j "$JAIL" ip4.addr
	atf_check cmp -s before etc/jail.conf

	atf_check -o match:"^IPv4: $JNET.1\$" \
	    "$JGC" -c "$SOCK" address remove -l "$JAIL" $JNET.2
	lo0_has $JNET.2 && atf_fail "alias not removed"

	atf_check -o match:"^IPv4: $JNET.1,$JNET.3\$" \
	    "$JGC" -c "$SOCK" address add -lp "$JAIL" $JNET.3
	atf_check -o match:"ip4.addr = $JNET.1, \"$JNET.3\";" \
	    cat etc/jail.conf
	atf_check -o ignore "$JGC" -c "$SOCK" restart "$JAIL"
	atf_check -o inline:"$JNET.1,$JNET.3\n" \
	    jls -j "$JAIL" ip4.addr
}
live_address_cleanup()
{
	cleanup
}

atf_test_case aliases cleanup
aliases_head()
{
	atf_set "descr" "Aliases jail(8) does not know about go with the jail"
	atf_set "require.user" "root"
}
aliases_body()
{
	start_daemon
	atf_check -o ignore "$JGC" -c "$SOCK" start "$JAIL"
	atf_check -o ignore "$JGC" -c "$SOCK" address add -l "$JAIL" $JNET.2
	lo0_has $JNET.2 || atf_fail "alias not added"
	# jail(8) -r removes the configured alias; arcana-agent the live one.
	atf_check -o save:stop.out "$JGC" -t -c "$SOCK" stop "$JAIL"
	atf_check -o match:'\[syscall\] ioctl\(SIOCDIFADDR\)' cat stop.out
	lo0_has $JNET.2 && atf_fail "live alias $JNET.2 left on lo0"
	lo0_has $JNET.1 && atf_fail "configured alias $JNET.1 left on lo0"

	# jail_remove(2) removes no aliases at all; arcana-agent does.
	atf_check -o ignore "$JGC" -c "$SOCK" start "$JAIL"
	lo0_has $JNET.1 || atf_fail "jail(8) did not add $JNET.1"
	atf_check -o ignore "$JGC" -c "$SOCK" kill "$JAIL"
	lo0_has $JNET.1 && atf_fail "alias $JNET.1 left after kill"
	true
}
aliases_cleanup()
{
	cleanup
}

atf_test_case routes cleanup
routes_head()
{
	atf_set "descr" "the real routing table through netlink: read, a route added with its cost and share, looked up, deleted; and each told by the kernel as an event, as an interface and its address are"
	atf_set "require.user" "root"
	atf_set "is.exclusive" "true"
}
routes_body()
{
	if ifconfig lo7 >/dev/null 2>&1 || route -n get 198.51.100.9 2>/dev/null | grep -q 'destination: 198.51.100.0'; then
		atf_skip "lo7 or a route to 198.51.100.0/24 is there already"
	fi
	touch mine
	start_daemon
	atf_check -o match:'"interface-name":"lo0"' -o match:'"fib":0,"flags":"[A-Z]*","gateway":"[^"]*","interface-name":"[^"]*","metric":[0-9]+' \
	    "$JGC" -c "$SOCK" net routes
	last=$("$JGC" -c "$SOCK" events | sed -E 's/^\{"last":([0-9]+).*/\1/')
	# Read by the daemon itself, from the kernel's own lists, as
	# netstat and sockstat would list them: what sockstat has, this has,
	# and in parts too.
	atf_check -o match:'^\{"socket":\[' "$JGC" -c "$SOCK" net connections
	pid=$(sockstat -46w | awk 'NR > 1 && $3 ~ /^[0-9]+$/ { print $3; exit }')
	atf_check -o match:"\"pid\":$pid," -o match:'"user":"' \
	    "$JGC" -c "$SOCK" net sockets
	atf_check -o match:'"command":"' "$JGC" -c "$SOCK" net sockets parts
	atf_check -o match:'netlink\(4\)' "$JGC" -t -c "$SOCK" net routes

	atf_check -o match:'done +route add 198.51.100.0/24 via 127.0.0.1' \
	    "$JGC" -c "$SOCK" route add 198.51.100.0/24 127.0.0.1 metric 7 weight 3
	atf_check -o match:'"destination":"198.51.100.0/24","fib":0,"flags":"UGS","gateway":"127.0.0.1","interface-name":"lo0","metric":7,[^}]*"weight":3' \
	    "$JGC" -c "$SOCK" net routes -4 198.51.100.
	atf_check -o match:'"best":\{"destination":"198.51.100.0",[^}]*"gateway":"127.0.0.1",[^}]*"prefixlen":24,"to":"198.51.100.9"' \
	    -o match:'"candidates":\[.*"destination":"198.51.100.0/24"' \
	    "$JGC" -c "$SOCK" route get 198.51.100.9
	atf_check -o match:'198.51.100.0/24 +127.0.0.1' netstat -rn4
	# The kernel told the agent of it, without being asked.
	atf_check -o match:'"kind":"route-add","data":\{"destination":"198.51.100.0/24","gateway":"127.0.0.1"' \
	    "$JGC" -c "$SOCK" events "$last"
	atf_check -o match:'done +route delete 198.51.100.0/24' \
	    "$JGC" -c "$SOCK" route delete 198.51.100.0/24 127.0.0.1 metric 7
	atf_check -o not-match:'198.51.100.0/24' netstat -rn4
	atf_check -o match:'"kind":"route-del","data":\{"destination":"198.51.100.0/24"' \
	    "$JGC" -c "$SOCK" events "$last"
	atf_check -s exit:1 -o match:'there is no such route' \
	    "$JGC" -c "$SOCK" route delete 198.51.100.0/24 127.0.0.1

	# Followed as they happen, the same events told to a subscriber.
	"$JGC" -c "$SOCK" events -f > follow.out 2>&1 &
	echo $! > follow.pid
	sleep 0.5
	# An interface that comes, and its address.
	atf_check ifconfig lo7 create
	atf_check ifconfig lo7 inet 127.0.77.1/24
	sleep 0.5
	atf_check -o match:'"kind":"link","data":\{"interface":"lo7"' \
	    -o match:'"kind":"address-add","data":\{"interface":"lo7","address":"127.0.77.1","prefixlen":24\}' \
	    "$JGC" -c "$SOCK" events "$last"
	# A route of two next hops, each with its share: two rows of one
	# route, and a nexthop group in the kernel.
	atf_check -o match:'done +route add 198.51.100.0/24 via 127.0.77.2@2,127.0.77.3' \
	    "$JGC" -c "$SOCK" route add 198.51.100.0/24 127.0.77.2@2,127.0.77.3
	atf_check -o save:ecmp.json "$JGC" -c "$SOCK" net routes -4 198.51.100.
	atf_check -o match:'"gateway":"127.0.77.2",[^}]*"path":[12],"paths":2,[^}]*"weight":2' \
	    -o match:'"gateway":"127.0.77.3",[^}]*"path":[12],"paths":2,[^}]*"weight":1' \
	    cat ecmp.json
	atf_check -o match:'"nh-gw":"127.0.77.[23]"' "$JGC" -c "$SOCK" net nhgroups
	# One of its ways deleted by its gateway: the other stays.
	atf_check -o match:'done' "$JGC" -c "$SOCK" route delete 198.51.100.0/24 127.0.77.3
	atf_check -o match:'"gateway":"127.0.77.2"' -o not-match:'127.0.77.3' \
	    "$JGC" -c "$SOCK" net routes -4 198.51.100.
	atf_check -o match:'done' "$JGC" -c "$SOCK" route delete 198.51.100.0/24
	# A route by a link-local gateway with its zone, as a router
	# advertisement gives one.
	atf_check -o match:'done +route add 2001:db8:79::/48 via fe80::1%lo0' \
	    "$JGC" -c "$SOCK" route add 2001:db8:79::/48 fe80::1%lo0
	atf_check -o match:'2001:db8:79::/48 +fe80::1%lo0' netstat -rn6
	atf_check -o match:'done' "$JGC" -c "$SOCK" route delete 2001:db8:79::/48
	# A neighbour, as ARP has it: listed by the kernel, and told as an
	# event when it comes and when it goes.
	ep=$(epair_create)
	echo "$ep" > epair
	atf_check ifconfig "$ep" inet 192.0.2.201/24 up
	atf_check arp -s 192.0.2.202 02:00:00:77:02:02
	sleep 0.5
	atf_check -o match:"\"address\":\"192.0.2.202\",\"family\":\"inet\",\"interface-name\":\"$ep\",\"lladdr\":\"02:00:00:77:02:02\",[^}]*\"state\":\"permanent\"" \
	    -o match:'"total":"[1-9]' "$JGC" -c "$SOCK" net neighbours -4 192.0.2.202
	atf_check -o match:'"kind":"neigh","data":\{"family":"inet","address":"192.0.2.202"' \
	    "$JGC" -c "$SOCK" events "$last"
	atf_check -o ignore arp -d 192.0.2.202
	sleep 0.5
	atf_check -o match:'"kind":"neigh-del","data":\{"family":"inet","address":"192.0.2.202"' \
	    "$JGC" -c "$SOCK" events "$last"
	atf_check ifconfig "$ep" destroy
	rm epair
	atf_check ifconfig lo7 destroy
	sleep 0.5
	atf_check -o match:'"kind":"link-del","data":\{"interface":"lo7"' \
	    "$JGC" -c "$SOCK" events "$last"
	kill "$(cat follow.pid)"
	atf_check -o match:'"kind":"link","data":\{"interface":"lo7"' \
	    -o match:'"kind":"route-add","data":\{[^}]*"destination":"198.51.100.0' \
	    -o match:'"kind":"neigh","data":\{"family":"inet","address":"192.0.2.202"' \
	    -o match:'"kind":"link-del","data":\{"interface":"lo7"' cat follow.out
}
routes_cleanup()
{
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	[ -f follow.pid ] && kill "$(cat follow.pid)" 2>/dev/null
	if [ -f mine ]; then
		route -q delete 198.51.100.0/24 >/dev/null 2>&1
		ifconfig lo7 destroy >/dev/null 2>&1
		[ -f epair ] && ifconfig "$(cat epair)" destroy >/dev/null 2>&1
	fi
	true
}

atf_test_case jail_network cleanup
jail_network_head()
{
	atf_set "descr" "a jail's own network (vnet) watched as the host's is: its interfaces, addresses and routes are events with its name, whether it was there before the agent or came after; and removed, it goes at once, not held"
	atf_set "require.user" "root"
}
jail_network_body()
{
	if jls -j arcw_n1 >/dev/null 2>&1 || jls -j arcw_n2 >/dev/null 2>&1; then
		atf_skip "a jail arcw_n1 or arcw_n2 is there already"
	fi
	touch mine
	atf_check -o ignore jail -c name=arcw_n1 vnet persist path=/
	start_daemon
	sleep 0.5
	atf_check -o match:'watching the network of jail arcw_n1' cat daemon.out
	last=$("$JGC" -c "$SOCK" events | sed -E 's/^\{"last":([0-9]+).*/\1/')
	atf_check -o ignore jail -c name=arcw_n2 vnet persist path=/
	sleep 0.5
	atf_check -o match:'watching the network of jail arcw_n2' cat daemon.out
	# An interface given to each, with an address and a route there:
	# told with the jail's name, the interface by the jail's own index.
	for n in 1 2; do
		ep=$(epair_create)
		echo "${ep%a}" >> epairs
		atf_check ifconfig "${ep%a}b" vnet "arcw_n$n"
		atf_check jexec "arcw_n$n" ifconfig "${ep%a}b" inet "192.0.2.2$n/24" up
		atf_check -o ignore jexec "arcw_n$n" route -q add 198.51.100.0/24 "192.0.2.3$n"
	done
	sleep 0.5
	atf_check -o save:ev.json "$JGC" -c "$SOCK" events "$last"
	for n in 1 2; do
		b=$(sed -n "${n}p" epairs)b
		atf_check -o match:"\"kind\":\"link\",\"jail\":\"arcw_n$n\",\"data\":\\{\"interface\":\"$b\"" \
		    -o match:"\"kind\":\"address-add\",\"jail\":\"arcw_n$n\",\"data\":\\{\"interface\":\"$b\",\"address\":\"192.0.2.2$n\",\"prefixlen\":24\\}" \
		    -o match:"\"kind\":\"route-add\",\"jail\":\"arcw_n$n\",\"data\":\\{\"destination\":\"198.51.100.0/24\",\"gateway\":\"192.0.2.3$n\",[^}]*\"interface-name\":\"$b\"" \
		    cat ev.json
	done
	# The host's own were not told as the jail's.
	atf_check -o not-match:'"kind":"route-add","data":\{"destination":"198.51.100.0/24"' cat ev.json
	# Its firewall on or off as the jail's own network has it, not
	# as the host's.
	if kldstat -q -m ipfw; then
		atf_check -o ignore jexec arcw_n1 sysctl net.inet.ip.fw.enable=0
		atf_check -o match:'"enabled":false' "$JGC" -j arcw_n1 -c "$SOCK" net ipfw
		atf_check -o ignore jexec arcw_n1 sysctl net.inet.ip.fw.enable=1
		atf_check -o match:'"enabled":true' "$JGC" -j arcw_n1 -c "$SOCK" net ipfw
	fi
	# Removed: no longer watched, and gone, not held dying by it.  A
	# vnet torn down with an address on an interface in it panics a
	# debug kernel: the epairs go first.
	while read -r e; do
		atf_check ifconfig "${e}a" destroy
	done < epairs
	atf_check -o ignore jail -r arcw_n1
	sleep 0.5
	atf_check -o match:'the network of jail arcw_n1 is not watched' cat daemon.out
	atf_check -s not-exit:0 -e match:"not found" jls -d -j arcw_n1 jid
	atf_check -o ignore jail -r arcw_n2
	sleep 0.5
	atf_check -s not-exit:0 -e match:"not found" jls -d -j arcw_n2 jid
}
jail_network_cleanup()
{
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	if [ -f mine ]; then
		[ -f epairs ] && while read -r e; do
			ifconfig "${e}a" destroy >/dev/null 2>&1
		done < epairs
		jail -r arcw_n1 >/dev/null 2>&1
		jail -r arcw_n2 >/dev/null 2>&1
	fi
	true
}

atf_test_case jail_plugins cleanup
jail_plugins_head()
{
	atf_set "descr" "a vnet jail's plugins are looked for as the jail sees its files: a program behind a link inside it is found, though the host has none; wg(8), the base system's, is no plugin"
	atf_set "require.user" "root"
}
jail_plugins_body()
{
	if jls -j arcw_p1 >/dev/null 2>&1; then
		atf_skip "a jail arcw_p1 is there already"
	fi
	[ -e /opt/local/sbin/squid ] &&
	    atf_skip "the host has /opt/local/sbin/squid: the link would lead to it"
	touch mine
	# Squid behind the jail's own /usr/local, a link to /opt/local
	# inside it: from the host, that link leads to the host's /opt.
	mkdir -p root/opt/local/sbin root/usr/bin
	printf '#!/bin/sh\n' > root/opt/local/sbin/squid
	printf '#!/bin/sh\n' > root/usr/bin/wg
	chmod +x root/opt/local/sbin/squid root/usr/bin/wg
	ln -s /opt/local root/usr/local
	atf_check -o ignore jail -c name=arcw_p1 vnet persist path="$(pwd)/root"
	start_daemon
	atf_check -o save:list.json "$JGC" --libxo json -c "$SOCK" list
	atf_check -o match:'"name":"arcw_p1"' cat list.json
	sed -n 's/.*"name":"arcw_p1"\(.*\)/\1/p' list.json > jail.json
	atf_check -o match:'"plugins": ?\[[^]]*"squid"' \
	    -o not-match:'"plugins": ?\[[^]]*"wireguard"' cat jail.json
	atf_check -o ignore jail -r arcw_p1
}
jail_plugins_cleanup()
{
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	[ -f mine ] && jail -r arcw_p1 >/dev/null 2>&1
	true
}

atf_test_case fw_trace cleanup
fw_trace_head()
{
	atf_set "descr" "packets followed through the real firewall by the kernel: pings to an address, each with the rule that passed it"
	atf_set "require.user" "root"
}
fw_trace_body()
{
	kldstat -q -m ipfw || atf_skip "ipfw(4) is not loaded"
	kldload -n dtraceall || atf_skip "no dtrace(4)"
	start_daemon
	# An address of its own: other tests' traffic to 127.0.0.1 would
	# fill the limit before a ping.
	atf_check ifconfig lo0 inet 127.0.0.57/32 alias
	ping -S 127.0.0.57 -c 6 -i 0.3 127.0.0.57 >/dev/null 2>&1 &
	atf_check -o save:trace.json "$JGC" -c "$SOCK" ipfw trace 127.0.0.57 3 4
	atf_check -o match:'"verdict":"pass","family":"inet","source":"127.0.0.57","destination":"127.0.0.57","proto":1,"sport":0,"dport":0,"rule":[0-9]+,"interface":"lo0","direction":"(in|out)"' \
	    -o match:'"seconds":3,"limit":4' cat trace.json
	# No more than asked for.
	atf_check -o inline:'4\n' sh -c "grep -o '\"ms\"' trace.json | wc -l | tr -d ' '"
}
fw_trace_cleanup()
{
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	ifconfig lo0 inet 127.0.0.57 -alias 2>/dev/null
	true
}

atf_test_case kmsg cleanup
kmsg_head()
{
	atf_set "descr" "the kernel's messages, numbered as they come and followed by their number, none twice"
	atf_set "require.user" "root"
}
kmsg_body()
{
	dmesg > /dev/null 2>&1 ||
	    atf_skip "kern.msgbuf cannot be read here: a jail needs allow.read_msgbuf"
	start_daemon
	atf_check -o save:k1.json "$JGC" -c "$SOCK" log @dmesg
	atf_check -o match:'"name":"@dmesg","lines":\[\{' \
	    -o match:'"seq":[0-9]+' -o match:'"position":[1-9][0-9]*' cat k1.json
	pos=$(sed -n 's/.*"position":\([0-9]*\).*/\1/p' k1.json)
	# After the newest: none of what was read again (the kernel may
	# have said more since).
	atf_check -o not-match:"\"seq\":$pos[,}]" -o match:'"position":[0-9]+' \
	    "$JGC" -c "$SOCK" log -f "$pos" @dmesg
	# The last lines, by their number, in order.
	atf_check -o save:k3.json "$JGC" -c "$SOCK" log -o 3 @dmesg
	atf_check -o inline:'3\n' sh -c "grep -o '\"seq\":' k3.json | wc -l | tr -d ' '"
	# A number from before the agent began: read anew.
	atf_check -o match:'"rotated":true' "$JGC" -c "$SOCK" log -f 99999999 @dmesg
}
kmsg_cleanup()
{
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	true
}

atf_test_case crash_event cleanup
crash_event_head()
{
	atf_set "descr" "a process the kernel ends by a signal that dumps" \
	    "core is an event, crash, with its name, jail and signal"
	atf_set "require.user" "root"
}
crash_event_body()
{
	[ "$(sysctl -n kern.logsigexit)" = 1 ] ||
	    atf_skip "kern.logsigexit is off: the kernel says no crash"
	dmesg > /dev/null 2>&1 ||
	    atf_skip "kern.msgbuf cannot be read here: a jail needs allow.read_msgbuf"
	start_daemon
	# The agent's first read of the buffer is what came before it.
	sleep 2
	# A stand-in of its own name crashes; no core is left (ulimit).
	cp /bin/sh ./arccrash
	./arccrash -c 'ulimit -c 0; kill -SEGV $$' || true
	for i in $(seq 1 50); do
		"$JGC" -c "$SOCK" events > ev.out 2>/dev/null
		grep -q '"process":"arccrash"' ev.out && break
		sleep 0.2
	done
	# The jail it ran in as the kernel's message says: 0 on a host; in
	# a jail its global jid, which the jail cannot learn from inside.
	jid=0
	[ "$(sysctl -n security.jail.jailed)" = 1 ] && jid='[0-9][0-9]*'

	atf_check -o match:'"kind":"crash"' \
	    -o match:"\"process\":\"arccrash\",\"jid\":$jid,\"jail\":\"\",\"uid\":0,\"signal\":11,\"core\":false" \
	    cat ev.out
}
crash_event_cleanup()
{
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	true
}

atf_test_case probe_other_fib cleanup
probe_other_fib_head()
{
	atf_set "descr" "a target in FIB 1 whose replies come in on lo0's FIB 0" \
	    "(a tunnelfib's case) heard by the FIB's listener, and still" \
	    "after the agent's restart"
	atf_set "require.user" "root"
	atf_set "is.exclusive" "true"
}
probe_other_fib_body()
{
	[ "$(sysctl -n net.fibs)" -ge 2 ] || atf_skip "net.fibs is 1"
	setfib 1 route -n get 127.0.0.1 >/dev/null 2>&1 ||
	    atf_skip "FIB 1 has no way to 127.0.0.1"
	echo '[{"id":"lo1","address":"127.0.0.1","fib":1,"kind":"icmp","interval":50,"eval":300,"down":3,"up":2,"timeout":300}]' \
	    > sdwan-probes.json
	start_daemon
	sleep 2
	atf_check -o match:'"id":"lo1","address":"127.0.0.1","family":"inet","fib":1,"state":"up"' \
	    "$JGC" -c "$SOCK" sdwan
	# Started again from its file: its listeners opened before the
	# prober's thread, kept.
	kill "$(cat daemon.pid)"
	while kill -0 "$(cat daemon.pid)" 2>/dev/null; do sleep 0.1; done
	start_daemon
	sleep 3
	atf_check -o match:'"id":"lo1",[^}]*"state":"up"' \
	    -o not-match:'"type":"tunnel"[^}]*"object":"lo1"[^}]*"cleared":false' \
	    "$JGC" -c "$SOCK" sdwan
}
probe_other_fib_cleanup()
{
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	true
}

# The agent's raw ICMP sockets now (procstat -f): ICMP's are "ICM",
# ICMPv6's a protocol procstat has no name for.
icmp_socks()
{
	procstat -f "$(cat daemon.pid)" | awk '$4 == "s" && ($9 == "ICM" ||
	    $9 == "IP?")' | wc -l | tr -d ' '
}

atf_test_case probe_shared_sockets cleanup
probe_shared_sockets_head()
{
	atf_set "descr" "the host's targets share one raw socket a FIB and a" \
	    "family: 64 on the loopback (32 inet, 32 inet6), two sockets, each" \
	    "target up by its own echo id; one in FIB 1 opens every FIB's" \
	    "socket of its family for the replies that come in on another" \
	    "table, and is up"
	atf_set "require.user" "root"
	atf_set "is.exclusive" "true"
}
probe_shared_sockets_body()
{
	local t i nf

	command -v python3 >/dev/null || atf_skip "no python3 to read the targets"
	DAEMON_ARGS="-d" start_daemon
	atf_check_equal 0 "$(icmp_socks)"
	# The kernel answers 200 echoes a second at most (net.inet.icmp.
	# icmplim): the 32 inet targets ask 128.
	t=
	for i in $(seq 1 32); do
		t="$t{\"id\":\"v4-$i\",\"address\":\"127.0.0.1\",\"kind\":\"icmp\",\"interval\":250,\"eval\":1000,\"up\":2},"
		t="$t{\"id\":\"v6-$i\",\"address\":\"::1\",\"kind\":\"icmp\",\"interval\":250,\"eval\":1000,\"up\":2},"
	done
	atf_check -o empty "$JGC" -c "$SOCK" sdwan probes "[${t%,}]"
	sleep 4
	atf_check -o save:sd.json "$JGC" -c "$SOCK" sdwan
	cat > up.py <<'EOF'
import json, sys
ts = json.load(open(sys.argv[1]))["targets"]
up = [t["id"] for t in ts if t["state"] == "up"]
print("%d targets, %d up" % (len(ts), len(up)))
EOF
	atf_check -o inline:'64 targets, 64 up\n' python3 -I up.py sd.json
	# One a family, not one a target.
	atf_check_equal 2 "$(icmp_socks)"
	atf_check -o inline:'1\n' grep -c 'probe: echo socket of FIB 0, inet$' \
	    daemon.out
	atf_check -o inline:'1\n' grep -c 'probe: echo socket of FIB 0, inet6$' \
	    daemon.out
	# A target in FIB 1: every FIB's inet socket (sixteen at most), its
	# replies heard whichever table they come in on.
	nf=$(sysctl -n net.fibs)
	[ "$nf" -ge 2 ] || atf_skip "net.fibs is 1"
	setfib 1 route -n get 127.0.0.1 >/dev/null 2>&1 ||
	    atf_skip "FIB 1 has no way to 127.0.0.1"
	[ "$nf" -gt 16 ] && nf=16
	# Raw sockets that take every table's packets: FIB 1's alone more.
	[ "$(sysctl -n net.inet.raw.bind_all_fibs)" = 0 ] || nf=2
	atf_check -o empty "$JGC" -c "$SOCK" sdwan probes \
	    "[${t%,},{\"id\":\"f1\",\"address\":\"127.0.0.1\",\"fib\":1,\"kind\":\"icmp\",\"interval\":100,\"eval\":500,\"up\":2}]"
	sleep 4
	atf_check -o save:sd2.json "$JGC" -c "$SOCK" sdwan
	atf_check -o inline:'65 targets, 65 up\n' python3 -I up.py sd2.json
	atf_check_equal "$((nf + 1))" "$(icmp_socks)"
	atf_check -o inline:"$nf\n" sh -c "grep -c 'probe: echo socket of FIB [0-9]*, inet\$' daemon.out"
	# That target gone: the other tables' sockets with it.
	atf_check -o empty "$JGC" -c "$SOCK" sdwan probes "[${t%,}]"
	sleep 1
	atf_check_equal 2 "$(icmp_socks)"
}
probe_shared_sockets_cleanup()
{
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	true
}

atf_test_case probe_dscp_packets cleanup
probe_dscp_packets_head()
{
	atf_set "descr" "targets of different DSCPs on one FIB's socket each" \
	    "send with their own: on lo0 (tcpdump), inet's echo requests of" \
	    "one target tos 0xb8 (46), another's 0x0; inet6's class 0x28 (10)" \
	    "and 0x0"
	atf_set "require.user" "root"
	atf_set "is.exclusive" "true"
}
probe_dscp_packets_body()
{
	command -v python3 >/dev/null || atf_skip "no python3 to read the capture"
	command -v tcpdump >/dev/null || atf_skip "no tcpdump"
	[ -c /dev/bpf ] || atf_skip "no /dev/bpf here for tcpdump"
	DAEMON_ARGS="-d" start_daemon
	tcpdump -l -n -v -i lo0 'icmp or icmp6' > dump.txt 2>/dev/null &
	echo $! > tcpdump.pid
	sleep 1
	atf_check -o empty "$JGC" -c "$SOCK" sdwan probes \
	    '[{"id":"ef","address":"127.0.0.1","kind":"icmp","dscp":46,"interval":100},{"id":"be","address":"127.0.0.1","kind":"icmp","interval":100},{"id":"af11","address":"::1","kind":"icmp","dscp":10,"interval":100},{"id":"be6","address":"::1","kind":"icmp","interval":100}]'
	sleep 3
	kill "$(cat tcpdump.pid)"
	sleep 0.5
	# Each target's echo id, as the agent says it when it makes it.
	sed -nE 's/.*probe: ([a-z0-9]+) \([^)]*\): echo id ([0-9]+)$/\1 \2/p' \
	    daemon.out > ids
	cat > tos.py <<'EOF'
import re, sys
ids = dict(l.split() for l in open("ids"))
tos = {}
lines = open("dump.txt").read().split("\n")
for i, l in enumerate(lines):
    m = re.search(r'^\S+ IP \(tos (0x[0-9a-f]+),', l)
    if m and i + 1 < len(lines):
        r = re.search(r'ICMP echo request, id (\d+),', lines[i + 1])
        if r:
            tos.setdefault(r.group(1), set()).add(m.group(1))
    m = re.search(r'IP6 \(class (0x[0-9a-f]+),.*ICMP6, echo request, id (\d+),',
        l)
    if m:
        tos.setdefault(m.group(2), set()).add(m.group(1))
for t in ("ef", "be", "af11", "be6"):
    print(t, " ".join(sorted(tos.get(ids.get(t, "-"), ["none"]))))
EOF
	atf_check -o inline:'ef 0xb8\nbe 0x0\naf11 0x28\nbe6 0x0\n' \
	    python3 -I tos.py
}
probe_dscp_packets_cleanup()
{
	[ -f tcpdump.pid ] && kill "$(cat tcpdump.pid)" 2>/dev/null
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	true
}

atf_test_case sdwan_probe cleanup
sdwan_probe_head()
{
	atf_set "descr" "a tunnel measured for real: the loopback pinged every 50 ms, up with its samples, and an address nothing routes to down, each an event; the steering's failover seen by the agent (arcana-steer, its steer-changed) and by the console's read"
	atf_set "require.user" "root"
	atf_set "is.exclusive" "true"
}
sdwan_probe_body()
{
	printf '#!/bin/sh\necho "ipfw $*" >> %s/ipfw.log\nexit 0\n' "$(pwd)" > fake-ipfw
	chmod +x fake-ipfw
	DAEMON_ARGS="-h $(pwd)/fake-ipfw"
	start_daemon
	last=$("$JGC" -c "$SOCK" events | sed -E 's/^\{"last":([0-9]+).*/\1/')
	atf_check -o empty "$JGC" -c "$SOCK" sdwan probes \
	    '[{"id":"lo","address":"127.0.0.1","interval":50,"eval":300,"down":2,"up":2,"timeout":200}]'
	sleep 2
	atf_check -o save:up.json "$JGC" -c "$SOCK" sdwan
	atf_check -o match:'"id":"lo","address":"127.0.0.1","family":"inet","fib":0,"state":"up"' \
	    -o match:'"samples":\[\[[0-9]+,[0-9.]+,[0-9.]+,0(\.0+)?,[0-9.]+,[0-9.]+,[1-9][0-9]*,[1-9][0-9]*,' cat up.json
	atf_check -o match:'"kind":"sdwan-tunnel","data":\{"id":"lo","address":"127.0.0.1","state":"up"' \
	    "$JGC" -c "$SOCK" events "$last"
	# A table with no way to it: every probe lost, down in two.
	[ "$(sysctl -n net.fibs)" -ge 3 ] ||
	    atf_skip "net.fibs is $(sysctl -n net.fibs): the probe nothing routes is in FIB 2"
	if setfib 2 route -n get 192.0.2.77 >/dev/null 2>&1; then
		atf_skip "fib 2 has a route to 192.0.2.77"
	fi
	# The steering follows the probes: the way through void first,
	# while nothing says it is down; once its probes do, the next one.
	atf_check -o empty "$JGC" -c "$SOCK" sdwan rules \
	    '{"set":30,"tables":[{"name":"swt_p_4","valtype":"ipv4"}],"rules":["12 fwd tablearg ip4 from any to table(swt_p_4)"]}'
	: > ipfw.log
	"$JGC" -c "$SOCK" notifications > notif.out 2>&1 &
	echo $! > notif.pid
	sleep 0.5
	atf_check -o empty "$JGC" -c "$SOCK" sdwan steer \
	    '{"entries":[{"table":"swt_p_4","prefix":"10.20.0.0/24","candidates":[{"id":"void","via":"100.64.0.9"},{"id":"lo","via":"100.64.0.1"}]}]}'
	atf_check -o match:'atomic add 10.20.0.0/24 100.64.0.9' cat ipfw.log
	atf_check -o match:'"changes":1,"chosen":"void","prefix":"10.20.0.0/24","reason":"preference",' \
	    "$JGC" -c "$SOCK" get steering
	atf_check -o empty "$JGC" -c "$SOCK" sdwan probes \
	    '[{"id":"lo","address":"127.0.0.1","interval":50,"eval":300,"down":2,"up":2,"timeout":200},{"id":"void","address":"192.0.2.77","fib":2,"interval":50,"eval":300,"down":2,"timeout":100}]'
	sleep 1.5
	atf_check -o match:'atomic add 10.20.0.0/24 100.64.0.1' cat ipfw.log
	# A failover seen on both: the agent's steering says why, and told
	# it as it happened; the console's read (arcanactl's sdwan is the
	# console's ysdwan.c) has it in the entry.
	atf_check -o match:'"id":"void","ipdv":"[0-9.]+","loss":"1.000000","non-selection-reason":"down","order":1,"selected":false,"state":"down","via":"100.64.0.9"\}' \
	    -o match:'"id":"lo","ipdv":"[0-9.]+","loss":"0.000000","order":2,"selected":true,"state":"up"' \
	    -o match:'"changes":2,"chosen":"lo","from":"void","prefix":"10.20.0.0/24","reason":"failover",' \
	    "$JGC" -c "$SOCK" get steering
	kill "$(cat notif.pid)"
	atf_check -o match:'"arcana-steer:steer-changed":\{"prefix":"10.20.0.0/24","reason":"preference","table":"swt_p_4","time":"[0-9T:-]+Z","to":"void"\}' \
	    -o match:'"arcana-steer:steer-changed":\{"from":"void","prefix":"10.20.0.0/24","reason":"failover","table":"swt_p_4","time":"[0-9T:-]+Z","to":"lo"\}' \
	    cat notif.out
	atf_check -o match:'"chosen":1,"candidates":\[\{"id":"void","via":"100.64.0.9","state":"down"\},\{"id":"lo","via":"100.64.0.1","state":"up"\}\],"reason":"failover","from":"void","since":[0-9]+,"changes":2' \
	    "$JGC" -c "$SOCK" sdwan
	atf_check -o match:'"id":"void","address":"192.0.2.77","family":"inet","fib":2,"state":"down"' \
	    -o match:'"id":"lo",[^}]*"state":"up"' "$JGC" -c "$SOCK" sdwan
	atf_check -o match:'"data":\{"id":"void","address":"192.0.2.77","state":"down","misses":[0-9]+' \
	    "$JGC" -c "$SOCK" events "$last"
	atf_check -o empty "$JGC" -c "$SOCK" sdwan probes '[]'
}
sdwan_probe_cleanup()
{
	[ -f notif.pid ] && kill "$(cat notif.pid)" 2>/dev/null
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	# Its rule and tables, which outlive the agent, gone from the
	# host's ipfw: only they, by their names.
	ipfw -S show 12 2>/dev/null | grep -q 'table(swt_p_4)' && \
	    ipfw -q delete 12
	ipfw -q table swt_p_4 destroy 2>/dev/null
	ipfw -q table swt_p_4_alt destroy 2>/dev/null
	true
}

atf_test_case sdwan_control cleanup
sdwan_control_head()
{
	atf_set "descr" "the control lane (PLAN-SDN-YANG 3.5.2), for real:" \
	    "over SCTP, while GET-SID dumps fill the association and are" \
	    "read slowly, a tunnel's probes going down and the steering's" \
	    "failover from it are told in that order, each within 200 ms"
	atf_set "require.user" "root"
	atf_set "require.progs" "openssl"
	atf_set "is.exclusive" "true"
}
sdwan_control_body()
{
	local c n

	has_sctp || atf_skip "the kernel has no SCTP"
	[ "$(sysctl -n net.fibs)" -ge 3 ] ||
	    atf_skip "net.fibs is $(sysctl -n net.fibs): the probe nothing routes is in FIB 2"
	if setfib 2 route -n get 192.0.2.77 >/dev/null 2>&1; then
		atf_skip "fib 2 has a route to 192.0.2.77"
	fi
	# The agent's certificate and the console's, from a CA of the case.
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
	    -nodes -keyout ca.key -out ca.pem -days 2 -subj /CN=ca \
	    -addext basicConstraints=critical,CA:TRUE \
	    -addext keyUsage=critical,keyCertSign >/dev/null 2>&1 ||
	    atf_fail "openssl: cannot make the CA"
	for c in server/IP:127.0.0.1/serverAuth,clientAuth \
	    client/DNS:console,URI:urn:arcana:role:console/clientAuth; do
		n=${c%%/*}
		openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
		    -keyout $n.key -out $n.csr -subj /CN=$n >/dev/null 2>&1
		printf 'subjectAltName=%s\nextendedKeyUsage=%s\n' \
		    "$(echo $c | cut -d/ -f2)" "${c##*/}" > $n.ext
		openssl x509 -req -in $n.csr -CA ca.pem -CAkey ca.key \
		    -CAcreateserial -days 2 -extfile $n.ext -out $n.pem \
		    >/dev/null 2>&1 || atf_fail "openssl: cannot sign $n"
	done
	printf '#!/bin/sh\necho "ipfw $*" >> %s/ipfw.log\nexit 0\n' "$(pwd)" > fake-ipfw
	chmod +x fake-ipfw
	PORT=$(jot -r 1 20000 59999)
	DAEMON_ARGS="-h $(pwd)/fake-ipfw -l tcp://127.0.0.1:$PORT -A ca.pem -C server.pem -K server.key"
	start_daemon
	atf_check -o empty "$JGC" -c "$SOCK" sdwan probes \
	    '[{"id":"lo","address":"127.0.0.1","interval":50,"eval":300,"down":2,"up":2,"timeout":200}]'
	atf_check -o empty "$JGC" -c "$SOCK" sdwan rules \
	    '{"set":30,"tables":[{"name":"swc_p_4","valtype":"ipv4"}],"rules":["12 fwd tablearg ip4 from any to table(swc_p_4)"]}'
	atf_check -o empty "$JGC" -c "$SOCK" sdwan steer \
	    '{"entries":[{"table":"swc_p_4","prefix":"10.20.0.0/24","candidates":[{"id":"void","via":"100.64.0.9"},{"id":"lo","via":"100.64.0.1"}]}]}'
	sleep 1
	cat > void.sh <<EOS
#!/bin/sh
exec "$JGC" -c "$SOCK" sdwan probes '[{"id":"lo","address":"127.0.0.1","interval":50,"eval":300,"down":2,"up":2,"timeout":200},{"id":"void","address":"192.0.2.77","fib":2,"interval":50,"eval":300,"down":2,"timeout":100}]'
EOS
	chmod +x void.sh
	atf_check -o save:lane.out "$(atf_get_srcdir)/ylane" \
	    "sctp://127.0.0.1:$PORT" ca.pem client.pem client.key 30 ./void.sh
	cat lane.out
	atf_check -o match:'atomic add 10.20.0.0/24 100.64.0.1' cat ipfw.log
	# The probes' word first, the failover it set off after.
	atf_check -o inline:'tunnel id=void state=down\nsteer-changed to=lo reason=failover\n' \
	    sh -c "grep -E '^(tunnel id=void|steer-changed)' lane.out | sed -E 's/ ms=.*//'"
	atf_check -o match:'^bulk [0-9.]+ MiB, [1-9][0-9]* dumps' cat lane.out
	atf_check sh -c "awk '/^max/ { exit !(\$2 < 200) }' lane.out"
	atf_check -o empty "$JGC" -c "$SOCK" sdwan probes '[]'
}
sdwan_control_cleanup()
{
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	# Its rule and tables, by their names, as sdwan_probe's.
	ipfw -S show 12 2>/dev/null | grep -q 'table(swc_p_4)' && \
	    ipfw -q delete 12
	ipfw -q table swc_p_4 destroy 2>/dev/null
	ipfw -q table swc_p_4_alt destroy 2>/dev/null
	true
}

atf_test_case sdwan_jail_edge cleanup
sdwan_jail_edge_head()
{
	atf_set "descr" "an SD-WAN edge that is a vnet jail, for real: its" \
	    "loopback probed from its own network (an ICMP socket the" \
	    "helper makes there), up, and a host's address the jail has no" \
	    "route to, down; its own ipfw given a set and steered"
	atf_set "require.user" "root"
	# Its rules are a commit of the host's interfaces as read a moment
	# before: another case's epair gone meanwhile fails it.
	atf_set "is.exclusive" "true"
}
sdwan_jail_edge_body()
{
	atf_check -o ignore jail -c name=arcw_sdj vnet persist path=/
	atf_check jexec arcw_sdj ifconfig lo0 inet 127.0.0.1/8 up
	start_daemon
	# 127.0.0.1 in the jail's network; 192.0.2.66 is on no route of it.
	atf_check -o empty "$JGC" -c "$SOCK" sdwan probes \
	    '{"jail":"arcw_sdj","targets":[{"id":"jlo","address":"127.0.0.1","interval":50,"eval":300,"down":2,"up":2,"timeout":200},{"id":"jvoid","address":"192.0.2.66","interval":50,"eval":300,"down":2,"timeout":100}]}'
	sleep 2
	atf_check -o match:'"id":"jlo","address":"127.0.0.1","family":"inet","jail":"arcw_sdj","fib":0,"state":"up"' \
	    -o match:'"id":"jvoid","address":"192.0.2.66","family":"inet","jail":"arcw_sdj","fib":0,"state":"(down|error)"' \
	    "$JGC" -c "$SOCK" sdwan
	# Its own ipfw, where the kernel has one.
	if jexec arcw_sdj ipfw show >/dev/null 2>&1; then
		atf_check -o empty "$JGC" -c "$SOCK" sdwan rules \
		    '{"jail":"arcw_sdj","set":30,"tables":[{"name":"sj_p4","valtype":"ipv4","entries":[]}],"rules":["00500 count ip from any to table(sj_p4)"]}'
		atf_check -o match:'^00500 .*count ip from any to table\(sj_p4\)' \
		    jexec arcw_sdj ipfw show 500
		atf_check -o empty "$JGC" -c "$SOCK" sdwan steer \
		    '{"jail":"arcw_sdj","entries":[{"table":"sj_p4","prefix":"10.20.0.0/24","candidates":[{"id":"jvoid","via":"100.64.0.9"},{"id":"jlo","via":"100.64.0.1"}]}]}'
		atf_check -o match:'10.20.0.0/24 100.64.0.1' \
		    jexec arcw_sdj ipfw table sj_p4 list
		# The host's ipfw has none of it.
		atf_check -s not-exit:0 -e ignore -o ignore ipfw table sj_p4 list
		atf_check -o empty "$JGC" -c "$SOCK" sdwan rules \
		    '{"jail":"arcw_sdj","set":30,"tables":[],"rules":[]}'
	fi
	atf_check -o match:'"kind":"sdwan-tunnel","data":\{"id":"jlo","address":"127.0.0.1","state":"up","misses":0,"jail":"arcw_sdj"\}' \
	    "$JGC" -c "$SOCK" events
	atf_check -o empty "$JGC" -c "$SOCK" sdwan probes '{"jail":"arcw_sdj","targets":[]}'
	# Its network's multicast state, its own: lo0 alone, in 224.0.0.1.
	atf_check -o match:'"interfaces":\[\{"groups":\[\{"family":"inet","group":"224.0.0.1".*"name":"lo0"\}\]' \
	    -o not-match:'"name":"(vtnet|em|igb|ix)[0-9]' \
	    -o match:'"settings":\[\{"name":"net.inet.igmp.default_version"' \
	    "$JGC" -c "$SOCK" -j arcw_sdj net multicast
}
sdwan_jail_edge_cleanup()
{
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	sleep 0.5
	jail -r arcw_sdj 2>/dev/null
	true
}

atf_test_case sdwan_altmark_lab cleanup
sdwan_altmark_lab_head()
{
	atf_set "descr" "alternate marking for real (RFC 9341, PLAN-SDN-YANG" \
	    "5.5.5): three vnet jails, a gre tunnel each pair over epairs," \
	    "each jail an edge with the marking's rules in its own ipfw set" \
	    "(ipfw show: the way out of a tunnel at 9, the way in at 11 after" \
	    "a class's setdscp and a flow's count by DSCP, before a flow's" \
	    "skip by the class and its coloured neighbour), the colour" \
	    "cleared before the jail's own rules, the class counted in both" \
	    "colours and EF again at the far end;" \
	    "traffic each way; a fifth of one tunnel's outer packets dropped" \
	    "one way (ipfw prob, in the jail): its blocks lose packets, every" \
	    "other way none, the loss in its RFC 9342 cluster alone"
	atf_set "require.user" "root"
	atf_set "timeout" "180"
	atf_set "is.exclusive" "true"
}
sdwan_altmark_lab_body()
{
	local d="$(pwd)" j e i n odd am

	for j in arcw_ama arcw_amb arcw_amc; do
		jls -j $j >/dev/null 2>&1 && atf_skip "a jail $j is there already"
	done
	for j in a b c; do
		atf_check -o ignore jail -c name=arcw_am$j vnet persist path=/
		jexec arcw_am$j ipfw show >/dev/null 2>&1 ||
		    atf_skip "no ipfw in a vnet jail"
		atf_check jexec arcw_am$j ifconfig lo0 inet 127.0.0.1/8 up
		# The jail's own rules, the admin's: what the marking's set
		# goes on to, and what it must never lose.
		atf_check -o ignore jexec arcw_am$j ipfw -q add 65000 allow ip \
		    from any to any
	done
	# The underlay: an epair each pair of jails.
	: > epairs
	for p in "a b 198.51.100.1 198.51.100.2" "a c 198.51.100.5 198.51.100.6" \
	    "b c 198.51.100.9 198.51.100.10"; do
		set -- $p
		e=$(epair_create) || atf_fail "no epair"
		echo "${e%a} $1 $2" >> epairs
		atf_check ifconfig ${e%a}a vnet arcw_am$1
		atf_check ifconfig ${e%a}b vnet arcw_am$2
		atf_check jexec arcw_am$1 ifconfig ${e%a}a inet $3/30 up
		atf_check jexec arcw_am$2 ifconfig ${e%a}b inet $4/30 up
	done
	# The tunnels, gre(4), each end in its jail's network.
	tun()
	{
		jexec arcw_am$1 ifconfig $2 create >/dev/null 2>&1 ||
		    atf_skip "no gre(4) in a vnet jail"
		atf_check jexec arcw_am$1 ifconfig $2 inet $3 $4 netmask \
		    255.255.255.255 tunnel $5 $6 up
	}
	tun a gre0 10.255.0.0 10.255.0.1 198.51.100.1 198.51.100.2
	tun b gre0 10.255.0.1 10.255.0.0 198.51.100.2 198.51.100.1
	tun a gre1 10.255.0.2 10.255.0.3 198.51.100.5 198.51.100.6
	tun c gre0 10.255.0.3 10.255.0.2 198.51.100.6 198.51.100.5
	tun b gre1 10.255.0.4 10.255.0.5 198.51.100.9 198.51.100.10
	tun c gre1 10.255.0.5 10.255.0.4 198.51.100.10 198.51.100.9
	start_daemon
	# Each jail an edge: its rules, its tunnels measured in blocks of
	# 2 s.  b's rules as the console's way into a tunnel has them: a
	# class marked (EF on b's pings to c), a flow's rule by DSCP that
	# only counts, a flow's that ends the pass (by the class and its
	# coloured neighbour, as the console writes a queue's), the skip to
	# the way out; at the way out, after the colour, the class counted
	# by colour.
	am()
	{
		atf_check -o empty "$JGC" -c "$SOCK" sdwan rules \
		    "{\"jail\":\"arcw_am$1\",\"set\":30,\"tables\":[],\"rules\":[$3\"99 count ip from any to any\"],\"altmark\":[{\"service\":\"lab\",\"period\":2,\"tunnels\":[$2]}]}"
	}
	am a '{"id":"lab/a-b","interface":"gre0","outer":"198.51.100.2","kind":"gre"},{"id":"lab/a-c","interface":"gre1","outer":"198.51.100.6","kind":"gre"}'
	am b '{"id":"lab/a-b","interface":"gre0","outer":"198.51.100.1","kind":"gre"},{"id":"lab/b-c","interface":"gre1","outer":"198.51.100.10","kind":"gre"}' \
	    '"11 setdscp 46 icmp from 10.255.0.4 to 10.255.0.5 out xmit gre1","11 count ip from any to any dscp 46 out xmit gre1","11 skipto 99 ip from any to any dscp 46,47 out xmit gre1","11 skipto 99 ip from any to any","99 count ip from any to any dscp 47 out xmit gre1","99 count ip from any to any dscp 46,47 out xmit gre1",'
	am c '{"id":"lab/a-c","interface":"gre0","outer":"198.51.100.5","kind":"gre"},{"id":"lab/b-c","interface":"gre1","outer":"198.51.100.9","kind":"gre"}'
	# 5.5.1's check: the rules in the jail's ipfw, set 30: the way out
	# of a tunnel at 9, the way in at 11; the outer rule the tunnel's
	# GRE alone.
	atf_check -o match:'^00011 +[0-9]+ +[0-9]+ set 30 setdscp tablearg ip from any to any out xmit gre0 lookup dscp:0x3e arcam0 // am 0\.0 mark lab/a-b' \
	    -o match:'^00009 +[0-9]+ +[0-9]+ set 30 count ip from any to any in recv gre1 dscp 1,3,5,.*,63 // am 0\.1 in 1 lab/a-c' \
	    -o match:'^00009 +[0-9]+ +[0-9]+ set 30 setdscp tablearg ip from any to any in recv gre0 lookup dscp:0x3e arcam_even // am 0\.0 unmark' \
	    -o match:'^00011 +[0-9]+ +[0-9]+ set 30 setdscp tablearg gre from any to 198\.51\.100\.2 out lookup dscp:0x3e arcam_even' \
	    -o match:'^65000 .*allow ip from any to any' \
	    jexec arcw_ama ipfw -S show
	# In b's: the class and the count of it before the colour, the
	# flow's skip after it.
	jexec arcw_amb ipfw -S show 11 > b11
	# (ipfw says EF for 46.)
	atf_check -o inline:'yes\n' sh -c "l() { grep -nE \"\$1\" b11 | head -1 | cut -d: -f1; }; test \$(l 'setdscp ef icmp') -lt \$(l 'count ip from any to any dscp ef out') && test \$(l 'count ip from any to any dscp ef out') -lt \$(l 'am 0.1 mark lab/b-c') && test \$(l 'am 0.1 mark lab/b-c') -lt \$(l 'skipto 99 ip from any to any dscp ef,47') && echo yes"
	atf_check -o match:'^46 ' jexec arcw_ama ipfw table arcam0 list
	atf_check -o match:'^46 ' jexec arcw_ama ipfw table arcam0_alt list
	# Nothing odd reaches the jail's own rules: the bit is cleared
	# before them on the way out of a tunnel.
	odd=$(seq -s, 1 2 63)
	atf_check -o ignore jexec arcw_amb ipfw -q add 1000 count ip from any \
	    to any in recv gre0 dscp $odd
	# c's own rule after the set: b's class arrives as EF.
	atf_check -o ignore jexec arcw_amc ipfw -q add 1001 count ip from any \
	    to any in recv gre1 dscp 46
	# A fifth of a's outer packets to b dropped (the underlay's loss,
	# one tunnel, one way).
	atf_check -o ignore jexec arcw_ama ipfw -q add 100 prob 0.2 deny gre \
	    from 198.51.100.1 to 198.51.100.2 out
	# Traffic each way of each tunnel, b's to c in a class (EF, b's
	# setdscp).
	jexec arcw_ama ping -q -i 0.01 -c 1200 10.255.0.1 >/dev/null 2>&1 &
	p1=$!
	jexec arcw_ama ping -q -i 0.01 -c 1200 10.255.0.3 >/dev/null 2>&1 &
	p2=$!
	jexec arcw_amb ping -q -i 0.01 -c 1200 10.255.0.5 >/dev/null 2>&1 &
	p3=$!
	# The pings alone: the agent is this shell's child too.
	wait $p1 $p2 $p3
	sleep 3
	atf_check -o save:sd.json "$JGC" -c "$SOCK" sdwan
	cat > amlab.py <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
rec = {}
for e in d.get("edges", []):
    for t in e.get("altmark", []):
        rec[(e["jail"][-1], t["tunnel"])] = {b["block"]: b for b in t["blocks"]}
ends = {"lab/a-b": "ab", "lab/a-c": "ac", "lab/b-c": "bc"}
links = []
for tun, (x, y) in ends.items():
    for f, t in ((x, y), (y, x)):
        a, b = rec[(f, tun)], rec[(t, tun)]
        common = [n for n in a if n in b and a[n]["valid"] and b[n]["valid"]]
        out = sum(a[n]["out_packets"] for n in common)
        lost = sum(a[n]["out_packets"] - b[n]["in_packets"] for n in common)
        links.append((tun, f, t, len(common), out, lost))
# RFC 9342 5.1: the input point is the from end's interface, the
# output the far end's; with a tunnel interface each end each link is
# its own cluster.
for tun, f, t, nb, out, lost in links:
    print(tun, f + ">" + t, "blocks", nb, "out", out, "lost", lost)
    assert nb >= 3 and out > 300, (tun, f, t, nb, out)
    if (tun, f) == ("lab/a-b", "a"):
        assert 0.1 * out < lost < 0.3 * out, (tun, f, out, lost)
    else:
        assert lost == 0, (tun, f, t, out, lost)
print("ok")
EOF
	atf_check -o match:'^ok$' -o match:'^lab/a-b a>b blocks' \
	    python3 -I amlab.py sd.json
	# Nothing odd counted by b's own rule: the colour was cleared.
	atf_check -o match:'^01000 +0 +0 ' jexec arcw_amb ipfw show 1000
	# b's class: every packet of it seen by the flow's count before the
	# colour, by the class and its neighbour after it; some in each
	# colour (dscp 47 alone in the odd blocks); all of it EF again at
	# c's own rule, none lost.
	cnt()
	{
		jexec arcw_am$1 ipfw show | grep -E "$2" | head -1 | \
		    awk '{ print $2 }'
	}
	all=$(cnt b '^00011 .*count ip from any to any dscp (ef|46) out xmit gre1$')
	wide=$(cnt b '^00099 .*count ip from any to any dscp (ef|46),47 out xmit gre1$')
	odd47=$(cnt b '^00099 .*count ip from any to any dscp 47 out xmit gre1$')
	atc=$(cnt c '^01001 ')
	echo "b's class: $all before the colour, $wide after, $odd47 odd, $atc at c"
	[ "${all:-0}" -ge 1000 ] || atf_fail "b's class counted $all before the colour"
	[ "$wide" = "$all" ] || atf_fail "after the colour $wide of $all"
	[ "$odd47" -gt $((all / 4)) ] && [ "$odd47" -lt $((all * 3 / 4)) ] ||
	    atf_fail "odd blocks' $odd47 of $all"
	[ "$atc" = "$all" ] || atf_fail "c's EF $atc of $all"
	cat > amcol.py <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
for e in d.get("edges", []):
    if e["jail"] != "arcw_amb":
        continue
    for t in e.get("altmark", []):
        if t["tunnel"] == "lab/b-c":
            c = {0: 0, 1: 0}
            for b in t["blocks"]:
                c[b["colour"]] += b["out_packets"]
            assert c[0] > 100 and c[1] > 100, c
            print("ok", c[0], c[1])
EOF
	atf_check -o match:'^ok [0-9]+ [0-9]+$' python3 -I amcol.py sd.json
	# Taken away with the set: the jail's own rules kept, no table left.
	atf_check -o empty "$JGC" -c "$SOCK" sdwan rules \
	    '{"jail":"arcw_ama","set":30,"tables":[],"rules":[]}'
	atf_check -o not-match:' set 30 ' -o match:'^00100 .*prob 0\.2[0-9]* deny' \
	    -o match:'^65000 .*allow ip from any to any' jexec arcw_ama ipfw -S show
	atf_check -s not-exit:0 -o ignore -e ignore jexec arcw_ama ipfw table \
	    arcam0 list
}
sdwan_altmark_lab_cleanup()
{
	local e j1 j2

	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	sleep 0.5
	# Every interface out of its jail before the jail goes: a vnet torn
	# down with one in it panics.
	for j1 in a b c; do
		for e in gre0 gre1; do
			jexec arcw_am$j1 ifconfig $e destroy 2>/dev/null
		done
	done
	if [ -f epairs ]; then
		while read e j1 j2; do
			ifconfig ${e}a -vnet arcw_am$j1 2>/dev/null
			ifconfig ${e}b -vnet arcw_am$j2 2>/dev/null
			ifconfig ${e}a destroy 2>/dev/null
		done < epairs
	fi
	for j1 in a b c; do
		jail -r arcw_am$j1 2>/dev/null
	done
	true
}

atf_test_case sdwan_flowexp_lab cleanup
sdwan_flowexp_lab_head()
{
	atf_set "descr" "flow records for real (PLAN-SDN-YANG 5.6.1): the" \
	    "agent's own edge (ng_ipfw's node is the host network's alone)," \
	    "a gre tunnel over an epair to a vnet jail: the ngtee rules in" \
	    "set 30 at 9, the ng_netflow and ng_ksocket nodes; UDP to 200" \
	    "ports across the tunnel; the jail's collector receives NetFlow" \
	    "version 9 datagrams with records, the last when the node is" \
	    "shut down with the flows taken away; a jail's edge refused"
	atf_set "require.user" "root"
	atf_set "timeout" "120"
	atf_set "is.exclusive" "true"
}
sdwan_flowexp_lab_body()
{
	local e R

	kldstat -q -m ng_ipfw || atf_skip "ng_ipfw is not loaded"
	kldstat -q -m ng_netflow || atf_skip "ng_netflow is not loaded"
	kldstat -q -m ng_ksocket || atf_skip "ng_ksocket is not loaded"
	# ng_ipfw's node is in the host's network alone: not in a vnet
	# jail's, which this one may be.
	ngctl info ipfw: >/dev/null 2>&1 ||
	    atf_skip "no ng_ipfw node in this network (a vnet jail's)"
	jls -j arcw_feb >/dev/null 2>&1 && atf_skip "a jail arcw_feb is there"
	ipfw set 30 list >/dev/null 2>&1 || atf_skip "no ipfw here"
	[ -z "$(ipfw set 30 list 2>/dev/null | grep -v '^65535')" ] ||
	    atf_skip "this host's ipfw has rules in set 30"
	atf_check -o ignore jail -c name=arcw_feb vnet persist path=/
	atf_check jexec arcw_feb ifconfig lo0 inet 127.0.0.1/8 up
	e=$(epair_create) || atf_fail "no epair"
	echo "${e%a}" > epair
	atf_check ifconfig ${e%a}b vnet arcw_feb
	atf_check ifconfig ${e%a}a inet 198.51.100.1/30 up
	atf_check jexec arcw_feb ifconfig ${e%a}b inet 198.51.100.2/30 up
	gre=$(ifconfig gre create) || atf_skip "no gre(4)"
	echo "$gre" > gre
	atf_check ifconfig $gre inet 10.255.0.0 10.255.0.1 netmask \
	    255.255.255.255 tunnel 198.51.100.1 198.51.100.2 up
	atf_check -o ignore jexec arcw_feb ifconfig gre0 create
	atf_check jexec arcw_feb ifconfig gre0 inet 10.255.0.1 10.255.0.0 \
	    netmask 255.255.255.255 tunnel 198.51.100.2 198.51.100.1 up
	# The jail's collector: each datagram's NetFlow version and record
	# count.
	cat > collector.py <<'EOS'
import socket, struct, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("198.51.100.2", 2055))
out = open(sys.argv[1], "a", buffering=1)
while True:
    d, a = s.recvfrom(65535)
    v, n = struct.unpack("!HH", d[:4])
    out.write("%d %d %d\n" % (v, n, len(d)))
EOS
	: > got
	jexec arcw_feb python3 -I "$(pwd)/collector.py" "$(pwd)/got" &
	echo $! > collector.pid
	start_daemon
	R='"tables":[],"rules":["99 count ip from any to any"]'
	# A jail's edge: refused, no ng_ipfw node there.
	atf_check -s exit:1 -e match:"host's edge" -o ignore "$JGC" -c "$SOCK" \
	    sdwan rules "{\"jail\":\"arcw_feb\",\"set\":30,$R,\"flowexp\":[{\"service\":\"lab\",\"collector\":\"198.51.100.1\",\"tunnels\":[{\"id\":\"lab/a-b\",\"interface\":\"gre0\"}]}]}"
	atf_check -o empty "$JGC" -c "$SOCK" sdwan rules \
	    "{\"set\":30,$R,\"flowexp\":[{\"service\":\"lab\",\"collector\":\"198.51.100.2\",\"inactive_timeout\":1,\"active_timeout\":5,\"tunnels\":[{\"id\":\"lab/a-b\",\"interface\":\"$gre\"}]}]}"
	atf_check -o match:"^00009 +[0-9]+ +[0-9]+ set 30 ngtee 61000 ip from any to any in recv $gre" \
	    -o match:"^00009 +[0-9]+ +[0-9]+ set 30 ngtee 61001 ip from any to any out xmit $gre" \
	    ipfw -S show
	atf_check -o match:'Name: arcnf0 +Type: netflow' \
	    -o match:'Name: arcnf0x +Type: ksocket' ngctl list
	# 200 flows across the tunnel, a UDP datagram to each of 200 ports.
	cat > send.py <<'EOS'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for p in range(20000, 20200):
    s.sendto(b"x" * 32, ("10.255.0.1", p))
EOS
	atf_check python3 -I send.py
	sleep 3
	# Taken away: the node shut down, what it held sent.
	atf_check -o empty "$JGC" -c "$SOCK" sdwan rules "{\"set\":30,$R}"
	sleep 1
	atf_check -o not-match:'arcnf' ngctl list
	atf_check -o not-match:'ngtee' ipfw -S show
	cat got
	atf_check -o match:'^9 ' cat got
	atf_check -o not-match:'^[^9]' cat got
	# Records for the 200 flows at least (and the templates).
	atf_check -o inline:'yes\n' awk '{ n += $2 } END { print ((n >= 200) ? "yes" : "no " n) }' got
}
sdwan_flowexp_lab_cleanup()
{
	local e

	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	[ -f collector.pid ] && kill "$(cat collector.pid)" 2>/dev/null
	sleep 0.5
	ipfw -q delete set 30 2>/dev/null
	for n in $(ngctl list 2>/dev/null | awk '/Name: arcnf[0-9]+ /{print $2}'); do
		ngctl shutdown $n: 2>/dev/null
	done
	[ -f gre ] && ifconfig "$(cat gre)" destroy 2>/dev/null
	jexec arcw_feb ifconfig gre0 destroy 2>/dev/null
	if [ -f epair ]; then
		e=$(cat epair)
		ifconfig ${e}b -vnet arcw_feb 2>/dev/null
		ifconfig ${e}a destroy 2>/dev/null
	fi
	jail -r arcw_feb 2>/dev/null
	true
}

atf_test_case sdwan_links cleanup
sdwan_links_head()
{
	atf_set "descr" "an SD-WAN edge's links watched for real: an epair's" \
	    "end down is an interface fault, up again cleared, as netlink" \
	    "tells the agent"
	atf_set "require.user" "root"
	# As sdwan_jail_edge's: a commit of the host's interfaces.
	atf_set "is.exclusive" "true"
}
sdwan_links_body()
{
	ep=$(epair_create) || atf_skip "no epair(4)"
	echo "$ep" > epair.name
	start_daemon
	atf_check -o empty "$JGC" -c "$SOCK" sdwan probes \
	    "{\"targets\":[],\"links\":[{\"interface\":\"$ep\",\"id\":\"uni-lab\",\"role\":\"uni\"}]}"
	# Made down: a fault at once.
	atf_check -o match:'"type":"interface","severity":"Major","was":"Major","object":"uni-lab","by":"link",[^}]*"cleared":false' \
	    "$JGC" -c "$SOCK" sdwan
	atf_check ifconfig "$ep" up
	atf_check ifconfig "${ep%a}b" up
	sleep 1
	atf_check -o match:'"object":"uni-lab","by":"link","description":"the UNI uni-lab has its link on '"$ep"' again","cleared":true' \
	    "$JGC" -c "$SOCK" sdwan
	atf_check ifconfig "$ep" down
	sleep 1
	atf_check -o match:'"object":"uni-lab","by":"link","description":"the UNI uni-lab has no link on '"$ep"'","cleared":false' \
	    "$JGC" -c "$SOCK" sdwan
	atf_check -o empty "$JGC" -c "$SOCK" sdwan probes '{"targets":[],"links":[]}'
}
sdwan_links_cleanup()
{
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	[ -f epair.name ] && ifconfig "$(cat epair.name)" destroy 2>/dev/null
	true
}

atf_test_case sctp_multihome cleanup
sctp_multihome_head()
{
	atf_set "descr" "an SCTP association multi-homed between two network" \
	    "stacks: the agent in one vnet jail bound to two addresses" \
	    "(--sctp-also), arcanactl in another with two of its own, two" \
	    "epairs between them; the association has a path over each," \
	    "one cut goes on over the other, and the cut one comes back"
	atf_set "require.user" "root"
	atf_set "timeout" "180"
	# Its paths judged by timers of 100 ms: not beside a loaded suite.
	atf_set "is.exclusive" "true"
}
sctp_multihome_body()
{
	local d="$(pwd)" port=24607 e0 e1 a b

	has_sctp || atf_skip "the kernel has no SCTP"
	[ "$(sysctl -n net.inet.sctp.ignore_loopback_iftype 2>/dev/null)" = 1 ] ||
	    atf_skip "the kernel's SCTP scopes by the interface's type"
	command -v openssl >/dev/null || atf_skip "no openssl"
	programs
	for j in arcw_ma arcw_mb; do
		jls -j $j >/dev/null 2>&1 && atf_skip "a jail $j is there already"
	done
	# A CA, the agent's certificate for both its addresses, a client's.
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
	    -keyout ca.key -out ca.pem -days 2 -subj /CN=lab-ca \
	    -addext basicConstraints=critical,CA:true \
	    -addext keyUsage=critical,keyCertSign >/dev/null 2>&1
	for n in server client; do
		openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
		    -keyout $n.key -out $n.csr -subj /CN=$n >/dev/null 2>&1
		if [ $n = server ]; then
			printf 'subjectAltName=IP:10.91.0.1,IP:10.92.0.1\nextendedKeyUsage=serverAuth\n' > $n.ext
		else
			printf 'subjectAltName=DNS:console,URI:urn:arcana:role:console\nextendedKeyUsage=clientAuth\n' > $n.ext
		fi
		openssl x509 -req -in $n.csr -CA ca.pem -CAkey ca.key \
		    -CAcreateserial -out $n.pem -days 2 -extfile $n.ext \
		    >/dev/null 2>&1 || atf_fail "no $n certificate"
	done
	atf_check -o ignore jail -c name=arcw_ma vnet persist path=/
	atf_check -o ignore jail -c name=arcw_mb vnet persist path=/
	e0=$(epair_create); e1=$(epair_create)
	echo "${e0%a} ${e1%a}" > epairs
	atf_check ifconfig $e0 vnet arcw_ma
	atf_check ifconfig ${e0%a}b vnet arcw_mb
	atf_check ifconfig $e1 vnet arcw_ma
	atf_check ifconfig ${e1%a}b vnet arcw_mb
	atf_check jexec arcw_ma ifconfig $e0 inet 10.91.0.1/24 up
	atf_check jexec arcw_ma ifconfig $e1 inet 10.92.0.1/24 up
	atf_check jexec arcw_mb ifconfig ${e0%a}b inet 10.91.0.2/24 up
	atf_check jexec arcw_mb ifconfig ${e1%a}b inet 10.92.0.2/24 up
	for j in arcw_ma arcw_mb; do
		atf_check jexec $j ifconfig lo0 inet 127.0.0.1/8 up
		# A failed path found in about a second, not half a minute:
		# each stack's own (net.inet.sctp is per vnet).
		atf_check -o ignore jexec $j sysctl net.inet.sctp.rto_min=100 \
		    net.inet.sctp.rto_initial=300 net.inet.sctp.rto_max=500 \
		    net.inet.sctp.path_rtx_max=1 net.inet.sctp.heartbeat_interval=200
	done
	mkdir -p etc/jail.conf.d
	: > etc/jail.conf
	# The agent in arcw_ma: TCP and SCTP on 10.91.0.1, SCTP on
	# 10.92.0.1 too.
	jexec arcw_ma "$JGD" -F -l "tcp://10.91.0.1:$port" \
	    --sctp-also 10.92.0.1 -A "$d/ca.pem" -C "$d/server.pem" \
	    -K "$d/server.key" -f "$d/etc/jail.conf" -D "$d/etc/jail.conf.d" \
	    -1 "$d/history.conf" > daemon.out 2>&1 &
	echo $! > daemon.pid
	a="-A $d/ca.pem -C $d/client.pem -K $d/client.key"
	for i in 1 2 3 4 5 6 7 8 9 10; do
		jexec arcw_mb "$JGC" -c "sctp://10.91.0.1:$port" $a hello \
		    >/dev/null 2>&1 && break
		sleep 0.5
	done
	# One association kept open: what happens, as it happens.
	jexec arcw_mb "$JGC" -c "sctp://10.91.0.1:$port" $a events -f \
	    > follow.out 2>&1 &
	echo $! > follow.pid
	sleep 1
	# From the agent's end: the follower's association has a path to
	# each of the client's addresses, both taken up.
	atf_check -o save:t1.json jexec arcw_mb "$JGC" \
	    -c "sctp://10.92.0.1:$port" $a transport
	atf_check -o match:'"transport":"sctp","up":true,"addresses":\[("10.91.0.1","10.92.0.1"|"10.92.0.1","10.91.0.1")\]' cat t1.json
	atf_check -o match:'"paths":\[[^]]*"address":"10.91.0.2","state":"active"' \
	    -o match:'"paths":\[[^]]*"address":"10.92.0.2","state":"active"' cat t1.json
	# The first path cut, at the client's end: what happens after goes
	# on over the other, on the same association.
	atf_check jexec arcw_mb ifconfig ${e0%a}b down
	atf_check jexec arcw_ma ifconfig lo7 create
	for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
		grep -q '"interface":"lo7"' follow.out && break
		sleep 0.5
	done
	atf_check -o match:'"kind":"link","data":\{"interface":"lo7"' cat follow.out
	kill -0 "$(cat follow.pid)" || atf_fail "the follower's association ended"
	atf_check -o save:t2.json jexec arcw_mb "$JGC" \
	    -c "sctp://10.92.0.1:$port" $a transport
	# The cut address no longer carries it: inactive, or taken out of
	# the association by the client itself (ASCONF, auto_asconf).
	atf_check -o match:'"address":"10.92.0.2","state":"active","srtt_ms":[0-9]+,"rto_ms":[0-9]+,"primary":true' \
	    -o not-match:'"address":"10.91.0.2","state":"active"' cat t2.json
	# The cut one back: added again (ASCONF) and taken up.
	atf_check jexec arcw_mb ifconfig ${e0%a}b up
	for i in 1 2 3 4 5 6 7 8 9 10; do
		jexec arcw_mb "$JGC" -c "sctp://10.92.0.1:$port" $a transport \
		    > t3.json 2>/dev/null
		grep -q '"address":"10.91.0.2","state":"active"' t3.json && break
		sleep 0.5
	done
	atf_check -o match:'"address":"10.91.0.2","state":"active"' cat t3.json
	atf_check jexec arcw_ma ifconfig lo7 destroy
}
sctp_multihome_cleanup()
{
	[ -f follow.pid ] && kill "$(cat follow.pid)" 2>/dev/null
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	sleep 0.5
	# Each interface out of its jail before the jail goes: a vnet torn
	# down with them in it can panic.
	if [ -f epairs ]; then
		for e in $(cat epairs); do
			ifconfig ${e}a -vnet arcw_ma 2>/dev/null
			ifconfig ${e}b -vnet arcw_mb 2>/dev/null
			ifconfig ${e}a destroy 2>/dev/null
		done
	fi
	jexec arcw_ma ifconfig lo7 destroy 2>/dev/null
	jail -r arcw_ma 2>/dev/null
	jail -r arcw_mb 2>/dev/null
	true
}

atf_test_case bird_live cleanup
bird_live_head()
{
	atf_set "descr" "BIRD for real between two vnet jails: eBGP over an" \
	    "epair, written as the console's BGP form writes a session," \
	    "Established, a route of each learned by the other; the agent" \
	    "reads the session's state and the routes through the real birdc"
	atf_set "require.user" "root"
	atf_set "timeout" "180"
}
bird_live_body()
{
	local d="$(pwd)" e j n

	[ -x /usr/local/sbin/bird ] || atf_skip "no BIRD (net/bird3)"
	for j in arcw_ba arcw_bb; do
		jls -j $j >/dev/null 2>&1 && atf_skip "a jail $j is there already"
	done
	atf_check -o ignore jail -c name=arcw_ba vnet persist path=/
	atf_check -o ignore jail -c name=arcw_bb vnet persist path=/
	e=$(epair_create)
	echo "${e%a}" > epair.name
	atf_check ifconfig $e vnet arcw_ba
	atf_check ifconfig ${e%a}b vnet arcw_bb
	atf_check jexec arcw_ba ifconfig $e inet 10.93.0.1/24 up
	atf_check jexec arcw_bb ifconfig ${e%a}b inet 10.93.0.2/24 up
	# Each as the BGP form writes a session (name, local AS, the
	# neighbour and its AS, a channel), and a route of its own to give.
	for n in a b; do
		if [ $n = a ]; then
			me=10.93.0.1 peer=10.93.0.2 las=65001 nas=65002 net=192.0.2.0/24
		else
			me=10.93.0.2 peer=10.93.0.1 las=65002 nas=65001 net=198.51.100.0/24
		fi
		cat > bird-$n.conf <<EOF
router id $me;

protocol device device1 {
}

protocol static own {
	ipv4;
	route $net blackhole;
}

protocol bgp peer_$n {
	description "the lab's other end";
	local as $las;
	neighbor $peer as $nas;
	ipv4 {
		import all;
		export where proto = "own";
	};
}
EOF
		atf_check /usr/local/sbin/bird -p -c bird-$n.conf
		jexec arcw_b$n /usr/local/sbin/bird -c "$d/bird-$n.conf" \
		    -s "$d/b$n.ctl" -P "$d/b$n.pid" || atf_fail "bird $n did not start"
	done
	# The agent's birdc: the real one, told jail a's socket.
	printf '#!/bin/sh\nexec /usr/local/sbin/birdc -s %s/ba.ctl "$@"\n' "$d" \
	    > birdc-a
	chmod +x birdc-a
	DAEMON_ARGS="-b $d/birdc-a"
	start_daemon
	for i in $(seq 1 60); do
		/usr/local/sbin/birdc -s ba.ctl show protocols peer_a 2>/dev/null |
		    grep -q Established && break
		sleep 1
	done
	atf_check -o match:'peer_a +BGP +--- +up .*Established' \
	    /usr/local/sbin/birdc -s ba.ctl show protocols peer_a
	# The agent's read of it, from the jail (arcana-bird's read action
	# on the jail's node): up and Established.
	atf_check -o save:bird.json "$JGC" -c "$SOCK" -j arcw_ba net bird
	atf_check -o match:'"info":"Established","name":"peer_a","since":"[^"]*","state":"up","table":"---","type":"BGP"' \
	    cat bird.json
	# The route b gave, learned by a, as the agent reads BIRD's table.
	for i in $(seq 1 20); do
		/usr/local/sbin/birdc -s ba.ctl show route 198.51.100.0/24 \
		    2>/dev/null | grep -q peer_a && break
		sleep 0.5
	done
	atf_check -o match:'198\.51\.100\.0/24' -o match:'peer_a' \
	    "$JGC" -c "$SOCK" -j arcw_ba bird routes
}
bird_live_cleanup()
{
	local d="$(pwd)"

	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	for n in a b; do
		[ -f b$n.pid ] && kill "$(cat b$n.pid)" 2>/dev/null
	done
	sleep 0.5
	# Its interfaces out of each jail before the jail goes.
	if [ -f epair.name ]; then
		e=$(cat epair.name)
		ifconfig ${e}a -vnet arcw_ba 2>/dev/null
		ifconfig ${e}b -vnet arcw_bb 2>/dev/null
		ifconfig ${e}a destroy 2>/dev/null
	fi
	jail -r arcw_ba 2>/dev/null
	jail -r arcw_bb 2>/dev/null
	true
}

atf_test_case pkg_lanes cleanup
pkg_lanes_head()
{
	atf_set "descr" "jobs of pkg in jails run four at once, a jail's own" \
	    "one after another, and the next job of another kind after all" \
	    "of them; a pkg that says nothing is stopped with its child in" \
	    "the jail, and one cancelled at work is stopped"
	atf_set "require.user" "root"
	atf_set "timeout" "120"
}
pkg_lanes_body()
{
	local d="$(pwd)" j id

	programs
	for j in arcw_k1 arcw_k2 arcw_k3 arcw_k4 arcw_ks arcw_kc; do
		jls -j $j >/dev/null 2>&1 && atf_skip "a jail $j is there already"
	done
	for j in arcw_k1 arcw_k2 arcw_k3 arcw_k4 arcw_ks arcw_kc; do
		atf_check -o ignore jail -c name=$j persist path=/
		echo $j >> jails.made
	done
	mkdir run etc etc/jail.conf.d
	: > etc/jail.conf
	# pkg, as the agent runs it: how many are at work when one starts,
	# a jail's twice at once said; arcw_ks silent with a child, as a
	# stalled download; arcw_kc silent until it is cancelled.
	cat > fake-pkg <<EOS
#!/bin/sh
jail=host
[ "\$1" = -j ] && { jail=\$2; shift 2; }
case "\$1" in
version) exit 1 ;;
-vv) exit 0 ;;
esac
[ -e $d/run/\$jail ] && echo "twice \$jail" >> $d/lanes.log
: > $d/run/\$jail
echo "\$jail \$(ls $d/run | wc -l | tr -d ' ')" >> $d/lanes.log
case "\$jail" in
arcw_ks|arcw_kc)
	# Stopped: no longer at work (its child is left to the agent).
	trap "rm -f $d/run/\$jail; exit 143" TERM
	sleep 300 &
	echo \$! > $d/\$jail.child
	wait ;;
*)	sleep 2
	echo "Your packages are up to date." ;;
esac
rm -f $d/run/\$jail
EOS
	chmod +x fake-pkg
	"$JGD" -F -l "unix:$d/s.sock" -P "$d/fake-pkg" --pkg-idle 5 \
	    -f "$d/etc/jail.conf" -D "$d/etc/jail.conf.d" \
	    -1 "$d/history.conf" > daemon.out 2>&1 &
	echo $! > daemon.pid
	for i in $(seq 1 50); do [ -S s.sock ] && break; sleep 0.1; done
	for j in arcw_ks arcw_kc arcw_k1 arcw_k1 arcw_k2 arcw_k3 arcw_k4; do
		"$JGC" -q -c "unix:$d/s.sock" pkg-upgrade -j $j >> queued.out ||
		    atf_fail "pkg-upgrade -j $j not queued"
	done
	# Then one of another kind: pkg on the host.
	"$JGC" -q -c "unix:$d/s.sock" pkg-upgrade >> queued.out
	id=$(awk '/in arcw_kc$/ { print $1 }' queued.out)
	for i in $(seq 1 50); do [ -s arcw_kc.child ] && break; sleep 0.1; done
	atf_check -o match:"^ *$id running" "$JGC" -c "unix:$d/s.sock" job-cancel $id
	for i in $(seq 1 300); do
		"$JGC" -c "unix:$d/s.sock" jobs | grep -q 'queued\|running' ||
		    break
		sleep 0.1
	done
	"$JGC" -c "unix:$d/s.sock" jobs > jobs.out
	cat lanes.log jobs.out
	atf_check -o not-match:'queued|running' cat jobs.out
	# Four at once at most, and four were.
	atf_check -o inline:'4\n' sh -c "awk '{ print \$2 }' lanes.log | sort -n | tail -1"
	atf_check -o not-match:twice cat lanes.log
	# The host's after every jail's, alone.
	atf_check -o match:'^host 1$' tail -1 lanes.log
	# The silent one stopped, its child with it; the cancelled one too.
	atf_check -o match:'failed +pkg upgrade in arcw_ks: pkg upgrade was killed: nothing came from it for 5 seconds' \
	    -o match:'failed +pkg upgrade in arcw_kc: cancelled while at work' \
	    -o match:'done +pkg upgrade in arcw_k1$' \
	    -o match:'done +pkg upgrade in arcw_k4$' \
	    -o match:'done +pkg upgrade$' cat jobs.out
	for j in arcw_ks arcw_kc; do
		atf_check -s not-exit:0 -e ignore kill -0 "$(cat $j.child)"
	done
}
pkg_lanes_cleanup()
{
	local j

	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	for j in arcw_ks arcw_kc; do
		[ -f $j.child ] && kill "$(cat $j.child)" 2>/dev/null
	done
	if [ -f jails.made ]; then
		for j in $(cat jails.made); do
			jail -r $j 2>/dev/null
		done
	fi
	true
}

atf_test_case sctp_loopback cleanup
sctp_loopback_head()
{
	atf_set "descr" "an SCTP listener on a router's loopback address alone" \
	    "(an address on lo0), with the kernel scoping by the address" \
	    "(net.inet.sctp.ignore_loopback_iftype): SCTP to that address" \
	    "from a peer elsewhere answered, and no warning said"
	atf_set "require.user" "root"
	atf_set "timeout" "120"
}
sctp_loopback_body()
{
	local d="$(pwd)" port=24611 e a

	has_sctp || atf_skip "the kernel has no SCTP"
	command -v openssl >/dev/null || atf_skip "no openssl"
	programs
	for j in arcw_la arcw_lb; do
		jls -j $j >/dev/null 2>&1 && atf_skip "a jail $j is there already"
	done
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
	    -keyout ca.key -out ca.pem -days 2 -subj /CN=lab-ca \
	    -addext basicConstraints=critical,CA:true \
	    -addext keyUsage=critical,keyCertSign >/dev/null 2>&1
	for n in server client; do
		openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
		    -keyout $n.key -out $n.csr -subj /CN=$n >/dev/null 2>&1
		if [ $n = server ]; then
			printf 'subjectAltName=IP:2001:db8:12::1\nextendedKeyUsage=serverAuth\n' > $n.ext
		else
			printf 'subjectAltName=DNS:console,URI:urn:arcana:role:console\nextendedKeyUsage=clientAuth\n' > $n.ext
		fi
		openssl x509 -req -in $n.csr -CA ca.pem -CAkey ca.key \
		    -CAcreateserial -out $n.pem -days 2 -extfile $n.ext \
		    >/dev/null 2>&1 || atf_fail "no $n certificate"
	done
	atf_check -o ignore jail -c name=arcw_la vnet persist path=/
	atf_check -o ignore jail -c name=arcw_lb vnet persist path=/
	e=$(epair_create)
	echo "${e%a}" > epair.name
	atf_check ifconfig $e vnet arcw_la
	atf_check ifconfig ${e%a}b vnet arcw_lb
	# The router's loopback, 2001:db8:12::1 on lo0; its link to the
	# client, 2001:db8:99::1.
	atf_check jexec arcw_la ifconfig lo0 inet6 ::1/128 up
	atf_check jexec arcw_la ifconfig lo0 inet6 2001:db8:12::1/128 alias
	atf_check jexec arcw_la ifconfig $e inet6 2001:db8:99::1/64 up
	atf_check jexec arcw_lb ifconfig lo0 inet6 ::1/128 up
	atf_check jexec arcw_lb ifconfig ${e%a}b inet6 2001:db8:99::2/64 up
	atf_check jexec arcw_lb route -q -6 add 2001:db8:12::1 2001:db8:99::1
	sleep 2	# duplicate address detection
	mkdir -p etc/jail.conf.d
	: > etc/jail.conf
	a="-A $d/ca.pem -C $d/client.pem -K $d/client.key"
	# The vnet's own value, as a new vnet takes it from the host's.
	atf_check -o inline:'1\n' jexec arcw_la sysctl -n net.inet.sctp.ignore_loopback_iftype
	jexec arcw_la "$JGD" -F -l "tcp://[2001:db8:12::1]:$port" \
	    -l "unix:$d/s.sock" \
	    -A "$d/ca.pem" -C "$d/server.pem" -K "$d/server.key" \
	    -f "$d/etc/jail.conf" -D "$d/etc/jail.conf.d" \
	    -1 "$d/history.conf" > daemon.out 2>&1 &
	echo $! > daemon.pid
	for i in $(seq 1 50); do [ -S s.sock ] && break; sleep 0.1; done
	sleep 0.5
	# The SCTP listener beside the TCP one, on lo0's address alone, up
	# and warned of nothing.
	atf_check -o save:t.json "$JGC" -c "unix:$d/s.sock" transport
	atf_check -o match:'"transport":"sctp","up":true' \
	    -o not-match:'"warning"' -o not-match:'loopback' cat t.json
	# Both answered from the other jail: TCP, and SCTP to the same
	# address on lo0.
	atf_check -o ignore jexec arcw_lb "$JGC" \
	    -c "tcp://[2001:db8:12::1]:$port" $a hello
	atf_check -o ignore jexec arcw_lb "$JGC" \
	    -c "sctp://[2001:db8:12::1]:$port" $a hello
	# Over SCTP the association's paths: the agent's lo0 address.
	atf_check -o match:'2001:db8:12::1' jexec arcw_lb "$JGC" \
	    -c "sctp://[2001:db8:12::1]:$port" $a transport
}
sctp_loopback_cleanup()
{
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	sleep 0.5
	if [ -f epair.name ]; then
		e=$(cat epair.name)
		ifconfig ${e}a -vnet arcw_la 2>/dev/null
		ifconfig ${e}b -vnet arcw_lb 2>/dev/null
		ifconfig ${e}a destroy 2>/dev/null
	fi
	jail -r arcw_la 2>/dev/null
	jail -r arcw_lb 2>/dev/null
	true
}

atf_test_case sdwan_record cleanup
sdwan_record_head()
{
	atf_set "descr" "what a rule logs to the routing socket (ipfw logdst rtsock) is the agent's record: a count rule on the loopback, a ping, the entry with the rule's comment and an event"
	atf_set "require.user" "root"
	atf_set "is.exclusive" "true"
}
sdwan_record_body()
{
	ipfw list >/dev/null 2>&1 || atf_skip "no ipfw here"
	ipfw list 65010 >/dev/null 2>&1 && atf_skip "rule 65010 is taken"
	start_daemon
	last=$("$JGC" -c "$SOCK" events | sed -E 's/^\{"last":([0-9]+).*/\1/')
	atf_check -o ignore ipfw -q add 65010 count log logdst rtsock logamount 100 icmp from 127.0.0.1 to 127.0.0.1 // security lab guard dst
	atf_check -o ignore ping -c 1 -q 127.0.0.1
	sleep 1
	atf_check -o match:'"record":\{"count":[1-9][0-9]*,"seq":[0-9]+,"untold":0,"last":\[\{"t":[0-9]+,"seq":[0-9]+,"rule":65010,"action":"count","src":"127.0.0.1","dst":"127.0.0.1","iface":"lo0","comment":"security lab guard dst"\}' \
	    "$JGC" -c "$SOCK" sdwan
	atf_check -o match:'"kind":"sdwan-security","data":\{"seq":[0-9]+,"rule":65010,"action":"count","src":"127.0.0.1","dst":"127.0.0.1","iface":"lo0","comment":"security lab guard dst"\}' \
	    "$JGC" -c "$SOCK" events "$last"
	ipfw -q delete 65010
}
sdwan_record_cleanup()
{
	ipfw -q delete 65010 2>/dev/null
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	true
}

atf_test_case resnapshot cleanup
resnapshot_head()
{
	atf_set "descr" "the newest snapshot of a dataset taken again under its name, on a pool of a memory disk made for it: newer, the same name, the older one untouched"
	atf_set "require.user" "root"
}
resnapshot_body()
{
	zpool list arcw_rs >/dev/null 2>&1 && atf_skip "a pool arcw_rs is there already"
	md=$(mdconfig -a -t swap -s 128m) || atf_skip "no memory disk"
	echo "$md" > md
	atf_check zpool create -O mountpoint=none arcw_rs "$md"
	atf_check zfs create arcw_rs/d
	atf_check zfs snapshot arcw_rs/d@old
	atf_check zfs snapshot arcw_rs/d@last
	before=$(zfs get -Hp -o value createtxg arcw_rs/d@last)
	start_daemon
	atf_check -o match:'done +zfs resnapshot arcw_rs/d@last' \
	    "$JGC" -c "$SOCK" zfs resnapshot arcw_rs/d@last
	after=$(zfs get -Hp -o value createtxg arcw_rs/d@last)
	atf_check test "$after" -gt "$before"
	atf_check -o inline:'arcw_rs/d@old\narcw_rs/d@last\n' \
	    zfs list -H -o name -s createtxg -t snapshot -d 1 arcw_rs/d
	atf_check -s exit:1 -o match:'not the newest snapshot' \
	    "$JGC" -c "$SOCK" zfs resnapshot arcw_rs/d@old
	# Held, it stays as it was, and nothing is left beside it.
	atf_check zfs hold keep arcw_rs/d@last
	atf_check -s exit:1 -o match:'kept as it was' \
	    "$JGC" -c "$SOCK" zfs resnapshot arcw_rs/d@last
	atf_check -o inline:"$after\n" zfs get -Hp -o value createtxg arcw_rs/d@last
	atf_check -o not-match:'resnap' zfs list -H -o name -t snapshot -r arcw_rs
	atf_check zfs release keep arcw_rs/d@last
}
resnapshot_cleanup()
{
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	if [ -f md ]; then
		zpool destroy -f arcw_rs >/dev/null 2>&1
		mdconfig -d -u "$(cat md)" >/dev/null 2>&1
	fi
	true
}

atf_test_case jail_make cleanup
jail_make_head()
{
	atf_set "descr" "jails made from a base snapshot on a pool of a memory disk made for it, by clone and by send, started, and taken away with their datasets"
	atf_set "require.user" "root"
}
jail_make_body()
{
	zpool list arcw_jm >/dev/null 2>&1 && atf_skip "a pool arcw_jm is there already"
	for j in arcw-jm1 arcw-jm2; do
		jls -j "$j" >/dev/null 2>&1 && atf_skip "a jail $j is there already"
	done
	md=$(mdconfig -a -t swap -s 256m) || atf_skip "no memory disk"
	echo "$md" > md
	r=$(pwd)/jails
	atf_check zpool create -O mountpoint=none arcw_jm "$md"
	atf_check zfs create -o mountpoint=none arcw_jm/jails
	atf_check zfs create -o mountpoint="$r/base" arcw_jm/jails/base
	echo "the base" > "$r/base/marker"
	atf_check zfs snapshot arcw_jm/jails/base@1
	start_daemon
	d=$(pwd)/etc
	# The defaults: each jail's path under the test's own, a host name,
	# and kept running without a command.
	printf 'path = "%s/${name}";\nhost.hostname = "${name}.example.org";\npersist;\n' "$r" > defaults.conf
	atf_check -o match:'done +jail defaults' "$JGC" -c "$SOCK" jailconf defaults defaults.conf
	# One by clone, one by send, each started.
	for j in arcw-jm1 arcw-jm2; do
		printf '.include "%s/jail.conf";\n%s {\n\tdevfs_ruleset = 4;\n}\n' "$d" "$j" > "$j.conf"
	done
	atf_check -o match:'done +jail make arcw-jm1 from arcw_jm/jails/base@1' \
	    "$JGC" -c "$SOCK" jailconf make arcw-jm1 arcw-jm1.conf arcw_jm/jails/arcw-jm1 arcw_jm/jails/base@1 clone "$r/arcw-jm1" start
	atf_check -o match:'done +jail make arcw-jm2 from arcw_jm/jails/base@1' \
	    "$JGC" -c "$SOCK" jailconf make arcw-jm2 arcw-jm2.conf arcw_jm/jails/arcw-jm2 arcw_jm/jails/base@1 send "$r/arcw-jm2" start
	atf_check -o inline:"$r/arcw-jm1\n" zfs get -H -o value mountpoint arcw_jm/jails/arcw-jm1
	atf_check -o inline:"arcw_jm/jails/base@1\n" zfs get -H -o value origin arcw_jm/jails/arcw-jm1
	atf_check -o inline:"-\n" zfs get -H -o value origin arcw_jm/jails/arcw-jm2
	atf_check -o inline:"the base\n" cat "$r/arcw-jm1/marker"
	atf_check -o inline:"the base\n" cat "$r/arcw-jm2/marker"
	atf_check -o inline:"$r/arcw-jm1 arcw-jm1.example.org\n" jls -j arcw-jm1 path host.hostname
	atf_check -o inline:"$r/arcw-jm2 arcw-jm2.example.org\n" jls -j arcw-jm2 path host.hostname
	# A running jail's file changed: the rest taken, its path kept.
	printf '.include "%s/jail.conf";\narcw-jm1 {\n\tdevfs_ruleset = 4;\n\tallow.raw_sockets;\n}\n' "$d" > e1.conf
	atf_check -o match:'done +jail edit arcw-jm1$' \
	    "$JGC" -c "$SOCK" jailconf edit arcw-jm1 e1.conf
	atf_check cmp -s e1.conf "$d/jail.conf.d/arcw-jm1.conf"
	printf '.include "%s/jail.conf";\narcw-jm1 {\n\tpath = "/elsewhere";\n}\n' "$d" > e2.conf
	atf_check -s exit:1 -o match:"arcw-jm1 runs with its root at $r/arcw-jm1: stop it" \
	    "$JGC" -c "$SOCK" jailconf edit arcw-jm1 e2.conf
	atf_check cmp -s e1.conf "$d/jail.conf.d/arcw-jm1.conf"
	# A host with no dataset for its jails yet: the one above made, not
	# mounted of its own; a jail refused takes it away again.
	printf '.include "%s/jail.conf";\narcw-jm3 {\n}\n' "$d" > arcw-jm3.conf
	atf_check -o match:'done +jail make arcw-jm3' \
	    "$JGC" -c "$SOCK" jailconf make arcw-jm3 arcw-jm3.conf arcw_jm/more/jails/arcw-jm3 arcw_jm/jails/base@1 clone "$r/arcw-jm3"
	atf_check -o inline:"off\n" zfs get -H -o value canmount arcw_jm/more/jails
	atf_check -o inline:"the base\n" cat "$r/arcw-jm3/marker"
	atf_check -o match:'done +jail remove arcw-jm3' \
	    "$JGC" -c "$SOCK" jailconf remove arcw-jm3 arcw_jm/more/jails/arcw-jm3
	printf '.include "%s/jail.conf";\nother {\n}\n' "$d" > arcw-jm4.conf
	atf_check -s exit:1 -o match:'not the one jail arcw-jm4' \
	    "$JGC" -c "$SOCK" jailconf make arcw-jm4 arcw-jm4.conf arcw_jm/new/jails/arcw-jm4 arcw_jm/jails/base@1 clone "$r/arcw-jm4"
	atf_check -s exit:1 -e ignore zfs list arcw_jm/new
	# Taken away: not with a dataset that is not its; then with its own,
	# stopped and destroyed.
	atf_check -s exit:1 -o match:'is not mounted at the jail' \
	    "$JGC" -c "$SOCK" jailconf remove arcw-jm1 arcw_jm/jails/arcw-jm2
	atf_check -o ignore jls -j arcw-jm1
	atf_check -o match:'done +jail remove arcw-jm1' \
	    "$JGC" -c "$SOCK" jailconf remove arcw-jm1 arcw_jm/jails/arcw-jm1
	atf_check -s exit:1 -o ignore -e ignore jls -j arcw-jm1
	atf_check -s exit:1 -e ignore zfs list arcw_jm/jails/arcw-jm1
	atf_check -o match:'done +jail remove arcw-jm2' \
	    "$JGC" -c "$SOCK" jailconf remove arcw-jm2 arcw_jm/jails/arcw-jm2
	atf_check -s exit:1 -e ignore zfs list arcw_jm/jails/arcw-jm2
	# The base stays as it was.
	atf_check -o inline:"arcw_jm/jails/base@1\n" zfs list -H -o name -t snapshot -r arcw_jm
}
jail_make_cleanup()
{
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	for j in arcw-jm1 arcw-jm2; do
		jail -r "$j" >/dev/null 2>&1
	done
	if [ -f md ]; then
		zpool destroy -f arcw_jm >/dev/null 2>&1
		mdconfig -d -u "$(cat md)" >/dev/null 2>&1
	fi
	true
}

atf_test_case carp cleanup
carp_head()
{
	atf_set "descr" "carp(4) between two vnet jails on one epair: a vhid made with its key by netlink, MASTER and BACKUP as their skews say, one told to step back, changed, and gone with its address; the key in no trace"
	atf_set "require.user" "root"
}
carp_body()
{
	kldstat -q -m carp || atf_skip "carp(4) is not loaded"
	if jls -j arcw_c1 >/dev/null 2>&1 || jls -j arcw_c2 >/dev/null 2>&1; then
		atf_skip "a jail arcw_c1 or arcw_c2 is there already"
	fi
	touch mine
	ep=$(epair_create)
	echo "${ep%a}" > epair
	atf_check -o ignore jail -c name=arcw_c1 vnet persist path=/ vnet.interface="${ep%a}a"
	atf_check -o ignore jail -c name=arcw_c2 vnet persist path=/ vnet.interface="${ep%a}b"
	atf_check jexec arcw_c1 ifconfig "${ep%a}a" inet 192.0.2.2/24 up
	atf_check jexec arcw_c2 ifconfig "${ep%a}b" inet 192.0.2.3/24 up
	start_daemon
	# Not kept (-p): these jails' rc.conf would be the host's.
	echo 'the-lab-key' > stdin.in
	atf_check < stdin.in -o match:"done +arcw_c1: ${ep%a}a: carp add vhid 7 192.0.2.1/24" \
	    -o not-match:'the-lab-key' "$JGC" -t -c "$SOCK" -j arcw_c1 carp add "${ep%a}a" 192.0.2.1/24 vhid=7 key
	echo 'the-lab-key' > stdin.in
	atf_check < stdin.in -o match:'done' \
	    "$JGC" -c "$SOCK" -j arcw_c2 carp add "${ep%a}b" 192.0.2.1/24 vhid=7 advskew=100 key
	sleep 4
	atf_check -o match:'"carp":true' -o match:'"carp":\[\{"advbase":1,"advskew":0,[^}]*"state":"MASTER","version":2,"vhid":7\}' \
	    -o match:'"address":"192.0.2.1","broadcast":"192.0.2.255","family":"inet","prefixlen":24,"vhid":7' \
	    "$JGC" -c "$SOCK" -j arcw_c1 net interfaces
	atf_check -o match:'"advbase":1,"advskew":100,[^}]*"state":"BACKUP","version":2' \
	    "$JGC" -c "$SOCK" -j arcw_c2 net interfaces
	# Told to step back: the other takes it.
	atf_check -o match:'done' "$JGC" -c "$SOCK" -j arcw_c1 carp set "${ep%a}a" vhid=7 state=backup
	sleep 5
	atf_check -o match:'"state":"BACKUP"' "$JGC" -c "$SOCK" -j arcw_c1 net interfaces
	atf_check -o match:'"advbase":1,"advskew":100,[^}]*"state":"MASTER","version":2' \
	    "$JGC" -c "$SOCK" -j arcw_c2 net interfaces
	# Changed: what is not given stays.
	atf_check -o match:'done' "$JGC" -c "$SOCK" -j arcw_c2 carp set "${ep%a}b" vhid=7 advskew=50
	atf_check -o match:'"advbase":1,"advskew":50' "$JGC" -c "$SOCK" -j arcw_c2 net interfaces
	atf_check -s exit:1 -o match:'version is set when it is made' \
	    "$JGC" -c "$SOCK" -j arcw_c2 carp set "${ep%a}b" vhid=7 version=3
	# Gone with its address.
	atf_check -o match:'done' "$JGC" -c "$SOCK" -j arcw_c1 carp remove "${ep%a}a" 192.0.2.1 vhid=7
	atf_check -o not-match:'"vhid":7' "$JGC" -c "$SOCK" -j arcw_c1 net interfaces
	atf_check ifconfig "${ep%a}a" -vnet arcw_c1
	atf_check ifconfig "${ep%a}b" -vnet arcw_c2
	atf_check -o ignore jail -r arcw_c1
	atf_check -o ignore jail -r arcw_c2
	atf_check ifconfig "${ep%a}a" destroy
}
carp_cleanup()
{
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	if [ -f mine ]; then
		e=$(cat epair 2>/dev/null)
		[ -n "$e" ] && ifconfig "${e}a" -vnet arcw_c1 >/dev/null 2>&1
		[ -n "$e" ] && ifconfig "${e}b" -vnet arcw_c2 >/dev/null 2>&1
		jail -r arcw_c1 >/dev/null 2>&1
		jail -r arcw_c2 >/dev/null 2>&1
		[ -n "$e" ] && ifconfig "${e}a" destroy >/dev/null 2>&1
	fi
	true
}

atf_test_case fwmatch_kernel cleanup
fwmatch_kernel_head()
{
	atf_set "descr" "path-check's ipfw walk (fwmatch.c) says what the" \
	    "kernel does: a ruleset in a vnet jail, packets sent at it from" \
	    "another, and the rule whose counter moved is the rule the walk" \
	    "names, for each"
	atf_set "require.user" "root"
}
fwmatch_kernel_body()
{
	local f="$(atf_get_srcdir)/fwmatch" ep a b

	kldstat -q -m ipfw || atf_skip "ipfw(4) is not loaded"
	if jls -j arcw_f1 >/dev/null 2>&1 || jls -j arcw_f2 >/dev/null 2>&1; then
		atf_skip "a jail arcw_f1 or arcw_f2 is there already"
	fi
	touch mine
	ep=$(epair_create)
	echo "${ep%a}" > epair
	a="${ep%a}a"
	b="${ep%a}b"
	atf_check -o ignore jail -c name=arcw_f1 vnet persist path=/ vnet.interface="$a"
	atf_check -o ignore jail -c name=arcw_f2 vnet persist path=/ vnet.interface="$b"
	atf_check jexec arcw_f1 ifconfig "$a" inet 192.0.2.2/24 up
	atf_check jexec arcw_f1 ifconfig "$a" inet 192.0.2.12/32 alias
	atf_check jexec arcw_f1 ifconfig lo0 up
	atf_check jexec arcw_f2 ifconfig "$b" inet 192.0.2.3/24 up
	atf_check jexec arcw_f2 ifconfig lo0 up
	# 198.51.100.0/24 is routed back elsewhere: verrevpath fails.
	atf_check -o ignore jexec arcw_f2 route add -net 198.51.100.0/24 -iface lo0
	atf_check jexec arcw_f1 ifconfig "$a" inet 198.51.100.7/32 alias
	# Out goes out: only what comes in is walked here.
	cat > rules <<EOF
add 00050 allow ip from any to any out
add 00100 allow ip from any to any via lo0
add 00300 deny ip from any to any not verrevpath in
add 00400 check-state :default
add 00500 count ip from any to any in recv $b
add 00600 skipto 1000 ip from 192.0.2.12 to any
add 00700 deny ip from table(bad) to any in
add 00800 allow tcp from any to me 22 in recv $b setup keep-state :default
add 00900 deny tcp from any to any 23 in
add 00950 allow icmp from any to me icmptypes 8 in
add 01000 deny udp from any to any 5000 in
add 01100 allow udp from any to { 192.0.2.3 or 192.0.2.9 } 53,123 in
add 01200 deny tcp from any to me 1024-2000 in
add 01300 allow udp from any to any in
add 65000 deny ip from any to any
EOF
	atf_check -o ignore jexec arcw_f2 sysctl net.inet.ip.fw.enable=1
	atf_check -o ignore jexec arcw_f2 ipfw -q flush
	atf_check -o ignore jexec arcw_f2 ipfw -q table bad create
	atf_check -o ignore jexec arcw_f2 ipfw -q table bad add 192.0.2.66/32
	atf_check -o ignore jexec arcw_f2 ipfw -q "$(pwd)/rules"
	jexec arcw_f2 ipfw list > list
	jexec arcw_f2 ipfw table all list > tables
	awk '$2 == "count" || $2 == "skipto" || $1 == "00050" {print $1}' \
	    list > notdeciding
	atf_check jexec arcw_f1 ifconfig "$a" inet 192.0.2.66/32 alias

	# One probe: the packet sent, the in rules (not count) whose
	# counters moved, against the walk's verdict for it.
	probe() {
		local from=$1 what=$2 port=$3 words before after got want
		before=$(jexec arcw_f2 ipfw show | awk '{print $1, $2}')
		case $what in
		icmp) jexec arcw_f1 ping -c 1 -t 1 -S $from 192.0.2.3 >/dev/null 2>&1
		      words="proto=icmp icmp=8" ;;
		udp)  echo x | jexec arcw_f1 nc -u -w 1 -s $from 192.0.2.3 $port >/dev/null 2>&1
		      words="proto=udp sport=40000 dport=$port" ;;
		tcp)  jexec arcw_f1 nc -z -w 1 -s $from 192.0.2.3 $port >/dev/null 2>&1
		      words="proto=tcp sport=40000 dport=$port syn" ;;
		esac
		after=$(jexec arcw_f2 ipfw show | awk '{print $1, $2}')
		# The rule that decided: one whose count rose, not of those
		# that only count or jump, nor the out one.
		got=$(printf '%s\n' "$after" | while read n c; do
			old=$(printf '%s\n' "$before" | awk -v n=$n '$1==n{print $2; exit}')
			[ "$c" != "${old:-0}" ] && echo $n
		done | grep -v -x -F -f notdeciding | head -1)
		rpf=rpf
		[ "$from" = 198.51.100.7 ] && rpf=
		want=$("$f" list tables local=192.0.2.3@$b in rcv=$b src=$from dst=192.0.2.3 $words $rpf reach | awk '{print $2}')
		echo "$from $what $port: kernel $got, walk $want"
		[ "$(printf %05d $want 2>/dev/null)" = "$got" ] || [ "$want" = "$got" ]
	}
	for p in "192.0.2.2 icmp" "192.0.2.2 tcp 22" "192.0.2.2 tcp 23" \
	    "192.0.2.2 tcp 1500" "192.0.2.2 tcp 80" "192.0.2.2 udp 53" \
	    "192.0.2.2 udp 5000" "192.0.2.2 udp 7000" "192.0.2.12 udp 5000" \
	    "192.0.2.12 udp 53" "192.0.2.66 icmp" "198.51.100.7 icmp"; do
		probe $p > out || atf_fail "$(cat out)"
		cat out
	done
	atf_check ifconfig "$a" -vnet arcw_f1
	atf_check ifconfig "$b" -vnet arcw_f2
	atf_check -o ignore jail -r arcw_f1
	atf_check -o ignore jail -r arcw_f2
	atf_check ifconfig "$a" destroy
}
fwmatch_kernel_cleanup()
{
	if [ -f mine ]; then
		e=$(cat epair 2>/dev/null)
		[ -n "$e" ] && ifconfig "${e}a" -vnet arcw_f1 >/dev/null 2>&1
		[ -n "$e" ] && ifconfig "${e}b" -vnet arcw_f2 >/dev/null 2>&1
		jail -r arcw_f1 >/dev/null 2>&1
		jail -r arcw_f2 >/dev/null 2>&1
		[ -n "$e" ] && ifconfig "${e}a" destroy >/dev/null 2>&1
	fi
	true
}

atf_test_case path_check cleanup
path_check_head()
{
	atf_set "descr" "path-check in a vnet jail between two others: what" \
	    "the router does with a packet and its reply, and why one does" \
	    "not get through: forwarding off, no send route, the firewall," \
	    "an asymmetric return with uRPF, a reply with no state"
	atf_set "require.user" "root"
}
path_check_body()
{
	local e1 e2 r

	kldstat -q -m ipfw || atf_skip "ipfw(4) is not loaded"
	for j in arcw_pc arcw_pr arcw_ps; do
		jls -j $j >/dev/null 2>&1 && atf_skip "a jail $j is there already"
	done
	touch mine
	e1=$(epair_create); e1=${e1%a}
	e2=$(epair_create); e2=${e2%a}
	echo "$e1 $e2" > epairs
	atf_check -o ignore jail -c name=arcw_pc vnet persist path=/ vnet.interface="${e1}a"
	atf_check -o ignore jail -c name=arcw_pr vnet persist path=/ vnet.interface="${e1}b" vnet.interface="${e2}a"
	atf_check -o ignore jail -c name=arcw_ps vnet persist path=/ vnet.interface="${e2}b"
	atf_check jexec arcw_pc ifconfig "${e1}a" inet 10.1.0.2/24 up
	atf_check jexec arcw_pr ifconfig "${e1}b" inet 10.1.0.1/24 up
	atf_check jexec arcw_pr ifconfig "${e2}a" inet 10.3.0.1/24 up
	atf_check jexec arcw_ps ifconfig "${e2}b" inet 10.3.0.2/24 up
	atf_check -o ignore jexec arcw_pc route add default 10.1.0.1
	atf_check -o ignore jexec arcw_ps route add default 10.3.0.1
	atf_check -o ignore jexec arcw_pr sysctl net.inet.ip.forwarding=1
	atf_check -o ignore jexec arcw_pr sysctl net.inet.ip.fw.enable=1
	atf_check -o ignore jexec arcw_pr ipfw -q flush
	atf_check -o ignore jexec arcw_pr ipfw -q add 65000 allow ip from any to any
	# The neighbours known, as a packet that went before would leave
	# them.
	atf_check -o ignore jexec arcw_pc ping -c 1 -t 2 10.3.0.2
	start_daemon

	# Through: in on e1b by the route back, out on e2a, the next hop
	# known, the reply back the same way.
	atf_check -o match:"\"ingress\":\{\"interface\":\"${e1}b\",\"how\":\"by the route back to the source\"\}" \
	    -o match:"\"route\":\{[^}]*\"interface\":\"${e2}a\"" \
	    -o match:'"neighbor":\{"address":"10.3.0.2","state":"[a-z]+"\}' \
	    -o match:'"symmetric":true' -o match:'"forwarding":true' \
	    -o match:'"severity":"ok","what":"Nothing here stops it, nor its reply"' \
	    -o not-match:'"severity":"bad"' "$JGC" -c "$SOCK" -j arcw_pr path-check -p tcp -P 22 10.1.0.2 10.3.0.2
	# Forwarding off.
	atf_check -o ignore jexec arcw_pr sysctl net.inet.ip.forwarding=0
	atf_check -o match:'"severity":"bad","what":"This host does not forward IPv4: net.inet.ip.forwarding is 0' \
	    "$JGC" -c "$SOCK" -j arcw_pr path-check -p icmp 10.1.0.2 10.3.0.2
	atf_check -o ignore jexec arcw_pr sysctl net.inet.ip.forwarding=1
	# No send route.
	atf_check -o match:'"severity":"bad","what":"No route to 10.9.0.5 in FIB 0: the send route is missing' \
	    "$JGC" -c "$SOCK" -j arcw_pr path-check -p icmp 10.1.0.2 10.9.0.5
	# The firewall: dropped going out, by its rule.
	atf_check -o ignore jexec arcw_pr ipfw -q add 01000 deny tcp from any to 10.3.0.2 22 out
	atf_check -o match:"\"severity\":\"bad\",\"what\":\"The firewall drops it going out by ${e2}a: rule 1000 \(01000 deny tcp from any to 10.3.0.2 22 out\)\"" \
	    -o match:'"out":\{"verdict":"deny","rule":1000' \
	    "$JGC" -c "$SOCK" -j arcw_pr path-check -p tcp -P 22 10.1.0.2 10.3.0.2
	atf_check -o not-match:'"severity":"bad"' "$JGC" -c "$SOCK" -j arcw_pr path-check -p tcp -P 80 10.1.0.2 10.3.0.2
	atf_check -o ignore jexec arcw_pr ipfw -q delete 1000
	# Asymmetric: the route back to the client by the other side; a
	# uRPF rule then drops what comes in.
	atf_check -o ignore jexec arcw_pr route add -host 10.1.0.2 -iface "${e2}a"
	atf_check -o match:"\"severity\":\"warn\",\"what\":\"Asymmetric: the request comes in on ${e1}b, the reply goes back by ${e2}a" \
	    -o match:'"symmetric":false' "$JGC" -c "$SOCK" -j arcw_pr path-check -i "${e1}b" -p icmp 10.1.0.2 10.3.0.2
	atf_check -o ignore jexec arcw_pr ipfw -q add 00500 deny ip from any to any not verrevpath in
	atf_check -o match:"\"severity\":\"bad\",\"what\":\"The firewall drops it coming in on ${e1}b: rule 500 " \
	    "$JGC" -c "$SOCK" -j arcw_pr path-check -i "${e1}b" -p icmp 10.1.0.2 10.3.0.2
	atf_check -o ignore jexec arcw_pr ipfw -q delete 500
	atf_check -o ignore jexec arcw_pr route delete -host 10.1.0.2
	# A reply with no state: let in only by one the request made.
	atf_check -o ignore jexec arcw_pr ipfw -q add 00600 allow tcp from 10.1.0.0/24 to any 22 in
	atf_check -o ignore jexec arcw_pr ipfw -q add 00700 allow tcp from 10.1.0.0/24 to any 22 out
	atf_check -o ignore jexec arcw_pr ipfw -q add 00800 deny tcp from any 22 to any
	atf_check -o match:"The firewall drops the reply coming in on ${e2}a: rule 800 \(00800 deny tcp from any 22 to any\) \(no state of the request's here to let it in\)" \
	    "$JGC" -c "$SOCK" -j arcw_pr path-check -p tcp -P 22 10.1.0.2 10.3.0.2
	atf_check -o ignore jexec arcw_pr ipfw -q add 00590 check-state
	atf_check -o ignore jexec arcw_pr ipfw -q delete 600
	atf_check -o ignore jexec arcw_pr ipfw -q add 00600 allow tcp from 10.1.0.0/24 to any 22 in keep-state
	atf_check -o match:'"reply_in":\{"verdict":"allow","rule":590,"text":"00590 check-state :default","by_state":true' \
	    -o not-match:'"severity":"bad"' "$JGC" -c "$SOCK" -j arcw_pr path-check -p tcp -P 22 10.1.0.2 10.3.0.2

	for i in "${e1}a:arcw_pc" "${e1}b:arcw_pr" "${e2}a:arcw_pr" "${e2}b:arcw_ps"; do
		atf_check ifconfig "${i%%:*}" -vnet "${i##*:}"
	done
	for j in arcw_pc arcw_pr arcw_ps; do
		atf_check -o ignore jail -r $j
	done
	atf_check ifconfig "${e1}a" destroy
	atf_check ifconfig "${e2}a" destroy
}
path_check_cleanup()
{
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	if [ -f mine ]; then
		read e1 e2 < epairs 2>/dev/null
		for i in "${e1}a:arcw_pc" "${e1}b:arcw_pr" "${e2}a:arcw_pr" "${e2}b:arcw_ps"; do
			[ -n "$e1" ] && ifconfig "${i%%:*}" -vnet "${i##*:}" >/dev/null 2>&1
		done
		for j in arcw_pc arcw_pr arcw_ps; do
			jail -r $j >/dev/null 2>&1
		done
		[ -n "$e1" ] && ifconfig "${e1}a" destroy >/dev/null 2>&1
		[ -n "$e2" ] && ifconfig "${e2}a" destroy >/dev/null 2>&1
	fi
	true
}

atf_test_case zfs_key cleanup
zfs_key_head()
{
	atf_set "descr" "A dataset's key typed: loaded, changed, kept nowhere, on a pool of a memory disk"
	atf_set "require.user" "root"
}
zfs_key_body()
{
	zpool list arcw_zk >/dev/null 2>&1 && atf_skip "a pool arcw_zk is there already"
	md=$(mdconfig -a -t swap -s 128m) || atf_skip "no memory disk"
	echo "$md" > md
	atf_check zpool create -O mountpoint=none arcw_zk "$md"
	echo 'first passphrase' > stdin.in
	atf_check < stdin.in zfs create -o encryption=on \
	    -o keyformat=passphrase -o keylocation=prompt -o mountpoint=none \
	    arcw_zk/enc
	atf_check zfs unload-key arcw_zk/enc
	atf_check -o inline:'unavailable\n' zfs get -H -o value keystatus arcw_zk/enc
	start_daemon
	# A wrong one: zfs's own words, nothing loaded.
	echo 'not the key' > stdin.in
	atf_check < stdin.in -s exit:1 -e match:'[Ii]ncorrect key' -o ignore \
	    "$JGC" -c "$SOCK" zfskey arcw_zk/enc
	echo 'first passphrase' > stdin.in
	atf_check < stdin.in -o ignore "$JGC" -c "$SOCK" zfskey arcw_zk/enc
	atf_check -o inline:'available\n' zfs get -H -o value keystatus arcw_zk/enc
	echo 'first passphrase' > stdin.in
	atf_check < stdin.in -s exit:1 -e match:'loaded already' -o ignore \
	    "$JGC" -c "$SOCK" zfskey arcw_zk/enc
	# Changed, and asked for at a prompt again.
	printf '\nsecond passphrase\n' > stdin.in
	atf_check < stdin.in -o ignore "$JGC" -c "$SOCK" zfskey -n arcw_zk/enc
	atf_check -o inline:'prompt\n' zfs get -H -o value keylocation arcw_zk/enc
	atf_check zfs unload-key arcw_zk/enc
	echo 'first passphrase' > stdin.in
	atf_check < stdin.in -s exit:1 -e match:'[Ii]ncorrect key' -o ignore \
	    "$JGC" -c "$SOCK" zfskey arcw_zk/enc
	# Not loaded: the key now first, then the new one.
	printf 'second passphrase\nthird passphrase\n' > stdin.in
	atf_check < stdin.in -o ignore \
	    "$JGC" -c "$SOCK" zfskey -n arcw_zk/enc
	atf_check zfs unload-key arcw_zk/enc
	echo 'third passphrase' > stdin.in
	atf_check < stdin.in -o ignore "$JGC" -c "$SOCK" zfskey arcw_zk/enc
	# Too short; and no key left anywhere, nor in what was said.
	printf '\nshort\n' > stdin.in
	atf_check < stdin.in -s exit:1 -e match:'8 characters at least' -o ignore \
	    "$JGC" -c "$SOCK" zfskey -n arcw_zk/enc
	ls -a /tmp | grep -q '^\.arcana-key\.' && atf_fail "a key file was left"
	grep -Eq '(first|second|third) passphrase' daemon.out && atf_fail "a key in the log"
	true
}
zfs_key_cleanup()
{
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	if [ -f md ]; then
		zpool destroy -f arcw_zk >/dev/null 2>&1
		mdconfig -d -u "$(cat md)" >/dev/null 2>&1
	fi
	true
}

atf_test_case devd_watch cleanup
devd_watch_head()
{
	atf_set "descr" "a memory disk made and destroyed, a pool made on it" \
	    "and exported: each told by devd(8), each an event"
	atf_set "require.user" "root"
}
devd_watch_body()
{
	[ -S /var/run/devd.seqpacket.pipe ] || atf_skip "devd(8) is not running"
	zpool list arcw_hw >/dev/null 2>&1 && atf_skip "a pool arcw_hw is there already"
	start_daemon
	"$JGC" -c "$SOCK" events -f > follow.out 2>&1 &
	echo $! > follow.pid
	sleep 1.2
	md=$(mdconfig -a -t swap -s 128m) || atf_skip "no memory disk"
	echo "$md" > md
	atf_check zpool create -O mountpoint=none arcw_hw "$md"
	sleep 1.5
	atf_check zpool export arcw_hw
	atf_check mdconfig -d -u "$md"
	rm md
	sleep 1.5
	kill "$(cat follow.pid)"
	atf_check -o match:"\"kind\":\"device\",\"data\":\\{\"cdev\":\"$md\",\"state\":\"created\"\\}" \
	    -o match:"\"kind\":\"device\",\"data\":\\{\"cdev\":\"$md\",\"state\":\"destroyed\"\\}" \
	    -o match:'"kind":"zfs","data":\{"type":"[a-z_]+","pool":"arcw_hw"\}' \
	    cat follow.out
}
devd_watch_cleanup()
{
	[ -f follow.pid ] && kill "$(cat follow.pid)" 2>/dev/null
	cleanup
	if [ -f md ]; then
		zpool destroy -f arcw_hw >/dev/null 2>&1
		mdconfig -d -u "$(cat md)" >/dev/null 2>&1
	fi
	true
}

atf_test_case monitors_probe cleanup
monitors_probe_head()
{
	atf_set "descr" "A tunnel monitor really probing: lo0 answers, up with samples of no loss; a gif's far end, found from the interface, does not, down, told as an event"
	atf_set "require.user" "root"
}
monitors_probe_body()
{
	start_daemon
	last=$("$JGC" -c "$SOCK" events | sed -E 's/^\{"last":([0-9]+).*/\1/')
	atf_check -o match:done "$JGC" -c "$SOCK" monitor set name=lo \
	    interface=lo0 address=127.0.0.1 interval=50 eval=200
	for i in $(seq 1 100); do
		"$JGC" -c "$SOCK" monitor | grep -q '"state":"up"' && break
		sleep 0.1
	done
	sleep 0.5
	atf_check -o match:'"id":"lo","address":"127.0.0.1","family":"inet","fib":0,"state":"up"' \
	    -o match:'"samples":\[\[[0-9]+,[0-9.e-]+,[0-9.e-]+,0(\.0*)?,' \
	    "$JGC" -c "$SOCK" monitor
	atf_check -o match:'"kind":"monitor","data":\{"id":"lo","address":"127.0.0.1","state":"up"' \
	    "$JGC" -c "$SOCK" events "$last"
	# A gif: its far end from the interface; nothing answers there.
	g=$(ifconfig gif create)
	echo "$g" > gif
	atf_check ifconfig "$g" inet 10.250.99.1 10.250.99.2 tunnel 127.0.0.1 \
	    127.0.0.2 up
	atf_check -o match:"done +monitor set g on $g" "$JGC" -c "$SOCK" \
	    monitor set name=g interface="$g" interval=50 timeout=100 down=2
	for i in $(seq 1 100); do
		"$JGC" -c "$SOCK" monitor | grep -q '"id":"g"[^}]*"state":"down"' &&
		    break
		sleep 0.1
	done
	atf_check -o match:'"id":"g","address":"10.250.99.2","family":"inet","fib":0,"state":"down"' \
	    "$JGC" -c "$SOCK" monitor
	atf_check -o match:"\"kind\":\"monitor\",\"data\":\\{\"id\":\"g\",\"address\":\"10.250.99.2\",\"state\":\"down\",\"misses\":[0-9]+,\"interface\":\"$g\"" \
	    "$JGC" -c "$SOCK" events "$last"
	atf_check -o match:done "$JGC" -c "$SOCK" monitor remove name=g
	atf_check -o match:done "$JGC" -c "$SOCK" monitor remove name=lo
}
monitors_probe_cleanup()
{
	[ -f gif ] && ifconfig "$(cat gif)" destroy 2>/dev/null
	cleanup
}

# Two vnet jails, an epair the underlay between them and a gif the
# overlay over it, A's underlay in its FIB 1 (the gif's tunnelfib);
# dummynet(4) shaping both: a pipe on A's underlay (delay and loss,
# which the overlay crosses too) and one on B's gif alone (delay the
# overlay has, the underlay not).
QOS_A=arc-tqa
QOS_B=arc-tqb

qos_lab_up()
{
	atf_check jail -c name=$QOS_A vnet persist path=/ host.hostname=$QOS_A
	atf_check jail -c name=$QOS_B vnet persist path=/ host.hostname=$QOS_B
	ep=$(epair_create)
	echo "$ep" > qos.epair
	atf_check ifconfig "$ep" vnet $QOS_A
	atf_check ifconfig "${ep%a}b" vnet $QOS_B
	atf_check -o ignore jexec $QOS_A sysctl net.fibs=2
	atf_check jexec $QOS_A ifconfig "$ep" fib 1
	atf_check jexec $QOS_A ifconfig "$ep" inet 192.0.2.1/30 up
	atf_check jexec $QOS_B ifconfig "${ep%a}b" inet 192.0.2.2/30 up
	atf_check -o save:qos.gifa jexec $QOS_A ifconfig gif create
	atf_check -o save:qos.gifb jexec $QOS_B ifconfig gif create
	ga=$(cat qos.gifa)
	gb=$(cat qos.gifb)
	atf_check jexec $QOS_A ifconfig "$ga" tunnelfib 1
	atf_check jexec $QOS_A ifconfig "$ga" tunnel 192.0.2.1 192.0.2.2
	atf_check jexec $QOS_A ifconfig "$ga" inet 10.99.0.1 10.99.0.2 up
	atf_check jexec $QOS_B ifconfig "$gb" tunnel 192.0.2.2 192.0.2.1
	atf_check jexec $QOS_B ifconfig "$gb" inet 10.99.0.2 10.99.0.1 up
	# The underlay: 20 ms and a fifth lost, each way's probes crossing
	# it once; the overlay alone: 30 ms more, at B.
	atf_check -o ignore jexec $QOS_A ipfw pipe 1 config delay 20ms plr 0.2
	atf_check -o ignore jexec $QOS_A ipfw add 100 pipe 1 ip from any to any \
	    out xmit "$ep"
	atf_check -o ignore jexec $QOS_B ipfw pipe 2 config delay 30ms
	atf_check -o ignore jexec $QOS_B ipfw add 100 pipe 2 ip from any to any \
	    out xmit "$gb"
}

# Taken down as vnet jails must be: what was made in them destroyed
# there, the epair's ends brought home first, then the jails.
qos_lab_down()
{
	[ -f qos.gifa ] && jexec $QOS_A ifconfig "$(cat qos.gifa)" destroy 2>/dev/null
	[ -f qos.gifb ] && jexec $QOS_B ifconfig "$(cat qos.gifb)" destroy 2>/dev/null
	jexec $QOS_A ipfw -q flush 2>/dev/null
	jexec $QOS_B ipfw -q flush 2>/dev/null
	jexec $QOS_A ipfw -q pipe flush 2>/dev/null
	jexec $QOS_B ipfw -q pipe flush 2>/dev/null
	if [ -f qos.epair ]; then
		ep=$(cat qos.epair)
		ifconfig "$ep" -vnet $QOS_A 2>/dev/null
		ifconfig "${ep%a}b" -vnet $QOS_B 2>/dev/null
		ifconfig "$ep" destroy 2>/dev/null
	fi
	jail -r $QOS_A $QOS_B >/dev/null 2>&1
	true
}

atf_test_case monitors_fib cleanup
monitors_fib_head()
{
	atf_set "descr" "A monitor in another FIB hears its replies, which" \
	    "come in on an interface of FIB 0"
	atf_set "require.user" "root"
}
monitors_fib_body()
{
	[ "$(sysctl -n net.fibs)" -ge 2 ] || atf_skip "one FIB alone here"
	[ "$(sysctl -n net.add_addr_allfibs)" = 0 ] ||
	    atf_skip "net.add_addr_allfibs is 1 here: an address is in every table already (net.add_addr_allfibs=0 in sysctl.conf)"
	ifconfig lo56 >/dev/null 2>&1 && atf_skip "lo56 is there already"
	atf_check -o ignore ifconfig lo56 create
	atf_check ifconfig lo56 inet 192.0.2.57/32
	# The address is FIB 0's; FIB 1 reaches it by a route of its own.
	atf_check -o ignore setfib 1 route add -host 192.0.2.57 -iface lo56
	start_daemon
	atf_check -o match:done "$JGC" -c "$SOCK" monitor set name=f1 \
	    address=192.0.2.57 fib=1 interval=50 eval=200
	for i in $(seq 1 100); do
		"$JGC" -c "$SOCK" monitor | grep -q '"id":"f1"[^}]*"state":"up"' &&
		    break
		sleep 0.1
	done
	atf_check -o match:'"id":"f1","address":"192.0.2.57","family":"inet","fib":1,"state":"up"' \
	    "$JGC" -c "$SOCK" monitor
	atf_check -o match:done "$JGC" -c "$SOCK" monitor remove name=f1
}
monitors_fib_cleanup()
{
	setfib 1 route delete -host 192.0.2.57 2>/dev/null
	ifconfig lo56 destroy 2>/dev/null
	cleanup
}

# stampd(8), stamp(1) and stampd's rc script, of the submodule stamp/:
# its objects beside Arcana's (MAKEOBJDIRPREFIX) or in its own obj/,
# else installed.
stamp_programs()
{
	local s=$(atf_get_srcdir) d

	SD= ; SS= ; SRC=
	for d in "$s/../../../stamp" "$s/../../../../stamp/obj"; do
		[ -x "$d/usr.sbin/stampd/stampd" ] || continue
		SD=$d/usr.sbin/stampd/stampd
		SS=$d/usr.bin/stamp/stamp
		SRC=$d/etc/rc.d/stampd
		break
	done
	if [ -z "$SD" ]; then
		SD=/usr/local/sbin/stampd
		SS=/usr/local/bin/stamp
		SRC=/usr/local/etc/rc.d/stampd
	fi
	[ -x "$SD" -a -x "$SS" -a -f "$SRC" ] ||
	    atf_skip "no stampd, stamp and rc script (the submodule stamp/)"
}

atf_test_case stampd_fib cleanup
stampd_fib_head()
{
	atf_set "descr" "A probe target in FIB 1: the agent sets stampd_fibs" \
	    "and reloads stampd, whose rc script starts one in FIB 1" \
	    "(stampd_fib) that answers there from the address the packet" \
	    "came to; FIB 0 not answered; the target gone, stopped"
	atf_set "require.user" "root"
	atf_set "timeout" "120"
}
stampd_fib_body()
{
	local i P

	[ "$(sysctl -n net.fibs)" -ge 2 ] || atf_skip "one FIB alone here"
	[ "$(sysctl -n net.inet.udp.bind_all_fibs)" = 0 ] ||
	    atf_skip "net.inet.udp.bind_all_fibs is 1: one socket for all"
	ifconfig lo58 >/dev/null 2>&1 && atf_skip "lo58 is there already"
	stamp_programs
	P=$(jot -r 1 20000 59999)
	atf_check -o ignore ifconfig lo58 create
	atf_check ifconfig lo58 fib 1
	atf_check ifconfig lo58 inet 192.0.2.59/32
	# A root whose rc.conf reads Arcana's file; stampd's script in the
	# rc.d directory the agent looks in.
	mkdir -p root/etc/defaults root/usr/local/etc rc.d
	cp /etc/defaults/rc.conf root/etc/defaults/
	printf 'rc_conf_files="/etc/rc.conf /etc/rc.conf.local /usr/local/etc/rc.conf.d/arcana"\n' \
	    > root/etc/rc.conf
	cp "$SRC" rc.d/stampd
	chmod +x rc.d/stampd
	# service(8) as the host's would be for stampd: the script run on
	# what the agent wrote, its port the case's, as nobody.
	cat > fake-service <<EOS
#!/bin/sh
echo "\$*" >> $(pwd)/service.log
[ "\$1" = stampd ] || exit 0
stampd_enable=NO stampd_fibs=
. $(pwd)/root/usr/local/etc/rc.conf.d/arcana 2>/dev/null
exec env stampd_enable="\$stampd_enable" stampd_fibs="\$stampd_fibs" \\
    stampd_program="$SD" stampd_flags="-p $P -u nobody" \\
    stampd_rundir="$(pwd)/run" /bin/sh "$SRC" "\$2"
EOS
	chmod +x fake-service
	DAEMON_ARGS="--root $(pwd)/root -R $(pwd)/rc.d -s $(pwd)/fake-service -d" \
	    start_daemon
	atf_check -o empty "$JGC" -c "$SOCK" sdwan probes \
	    '[{"id":"t1","address":"192.0.2.59","fib":1}]'
	for i in $(seq 1 100); do
		[ -f run/fib1.pid ] && break
		sleep 0.1
	done
	atf_check -o match:'^stampd_fibs="1"$' \
	    cat root/usr/local/etc/rc.conf.d/arcana
	atf_check -o match:'^stampd reload$' cat service.log
	for i in $(seq 1 50); do
		setfib 1 "$SS" -p $P -W 0.2 192.0.2.59 | grep -q '^len=44' &&
		    break
	done
	atf_check -o match:"^len=44 from=192\.0\.2\.59 seq=0 ssid=3 sseq=10 ttl=77 rttl=255 echo=ok order=ok clock=ok serr=ok mbz=ok pad=ok " \
	    setfib 1 "$SS" -p $P -q 10 -s 3 -t 77 -S 40862 192.0.2.59
	atf_check -o match:'^len=44 .* seq=1 ssid=3 sseq=11 ' \
	    setfib 1 "$SS" -p $P -q 11 -s 3 -S 40862 192.0.2.59
	atf_check -o inline:'nobody\n' ps -o user= -p "$(cat run/fib1.pid)"
	# FIB 0: no service there, nothing listening.
	atf_check -s exit:2 -o inline:'none\n' "$SS" -p $P -W 0.5 127.0.0.1
	# The target gone: Arcana's settings taken out, stampd stopped.
	atf_check -o empty "$JGC" -c "$SOCK" sdwan probes '[]'
	for i in $(seq 1 100); do
		grep -q '^stampd onestop$' service.log && break
		sleep 0.1
	done
	atf_check -o not-match:'stampd' cat root/usr/local/etc/rc.conf.d/arcana
	# service(8) logged as it starts: stopped a moment later.
	for i in $(seq 1 50); do
		[ -f run/fib1.pid ] && pkill -0 -F run/fib1.pid 2>/dev/null ||
		    break
		sleep 0.1
	done
	atf_check -s exit:2 -o inline:'none\n' \
	    setfib 1 "$SS" -p $P -W 0.5 192.0.2.59
}
stampd_fib_cleanup()
{
	local pf

	for pf in run/fib*.pid; do
		[ -f "$pf" ] && kill "$(cat "$pf")" 2>/dev/null
	done
	ifconfig lo58 destroy 2>/dev/null
	cleanup
}

# STAMP's loss each way (PLAN-SDN-YANG 5.1.3): stampd in a vnet jail
# behind an epair, four addresses on its end, each a target of the
# agent's.
STL_J=arc-tsl
STL_NET=198.18.62

atf_test_case stamp_loss cleanup
stamp_loss_head()
{
	atf_set "descr" "Arcana's far ends measured by STAMP: stampd in a" \
	    "vnet jail across an epair, a fifth of the packets lost on the" \
	    "way in to one address and of the replies on the way out of" \
	    "another (dummynet plr, else ipfw prob deny when dummynet is" \
	    "not loaded); the agent's loss forward on the one and backward" \
	    "on the other, none the other way; a refused STAMP port pinged" \
	    "instead, a breakout's beacon (kind icmp) pinged anyway"
	atf_set "require.user" "root"
	atf_set "timeout" "120"
}
stamp_loss_body()
{
	local ep i f b P

	kldstat -q -m ipfw || atf_skip "ipfw(4) is not loaded"
	# A new vnet's ipfw starts with the default rule: deny would cut it.
	[ "$(sysctl -n net.inet.ip.fw.default_to_accept)" = 1 ] ||
	    atf_skip "net.inet.ip.fw.default_to_accept is not 1"
	jls -j $STL_J >/dev/null 2>&1 && atf_skip "a jail $STL_J exists"
	stamp_programs
	P=$(jot -r 1 20000 59999)
	atf_check jail -c name=$STL_J vnet persist path=/ host.hostname=$STL_J
	ep=$(epair_create)
	echo "$ep" > stl.epair
	atf_check ifconfig "$ep" inet $STL_NET.1/29 up
	atf_check ifconfig "${ep%a}b" vnet $STL_J
	atf_check jexec $STL_J ifconfig "${ep%a}b" inet $STL_NET.2/29 up
	for i in 3 4 5; do
		atf_check jexec $STL_J ifconfig "${ep%a}b" inet $STL_NET.$i/32 \
		    alias
	done
	jexec $STL_J "$SD" -d -u nobody -r 0 -R 0 -p $P > stl.d.out 2>&1 &
	echo $! > stl.spid
	for i in $(seq 1 100); do
		grep -q started stl.d.out && break
		sleep 0.05
	done
	grep -q started stl.d.out || atf_fail "stampd: $(cat stl.d.out)"
	# .2: a fifth lost on the way in; .3: a fifth of the replies lost
	# on the way out; .4: its port refused; .5: as it is.
	if kldstat -q -m dummynet; then
		atf_check -o ignore jexec $STL_J ipfw pipe 1 config plr 0.2
		atf_check -o ignore jexec $STL_J ipfw pipe 2 config plr 0.2
		atf_check -o ignore jexec $STL_J ipfw add 100 pipe 1 udp from \
		    any to $STL_NET.2 dst-port $P in
		atf_check -o ignore jexec $STL_J ipfw add 110 pipe 2 udp from \
		    $STL_NET.3 $P to any out
	else
		echo "dummynet(4) not loaded: ipfw prob 0.2 deny instead"
		atf_check -o ignore jexec $STL_J ipfw add 100 prob 0.2 deny udp \
		    from any to $STL_NET.2 dst-port $P in
		atf_check -o ignore jexec $STL_J ipfw add 110 prob 0.2 deny udp \
		    from $STL_NET.3 $P to any out
	fi
	atf_check -o ignore jexec $STL_J ipfw add 120 unreach port udp from \
	    any to $STL_NET.4 dst-port $P in
	DAEMON_ARGS="-d --stamp-port $P" start_daemon
	# down 10: twenty per cent lost never makes ten in a row.
	t='"interval":20,"eval":1000,"timeout":300,"down":10'
	atf_check -o empty "$JGC" -c "$SOCK" sdwan probes \
	    "[{\"id\":\"fwd\",\"address\":\"$STL_NET.2\",$t},{\"id\":\"back\",\"address\":\"$STL_NET.3\",$t},{\"id\":\"refused\",\"address\":\"$STL_NET.4\",$t},{\"id\":\"clean\",\"address\":\"$STL_NET.5\",$t},{\"id\":\"bo:gw\",\"address\":\"$STL_NET.2\",\"kind\":\"icmp\",$t}]"
	sleep 10
	atf_check -o save:stl.json "$JGC" -c "$SOCK" sdwan
	# Each target's last window: lost forward F, backward B all along.
	for i in fwd back clean; do
		grep "probe: $i: stamp (stateful reflector): " daemon.out | tail -1 \
		    > stl.$i
		[ -s stl.$i ] || atf_fail "$i not measured by STAMP: $(cat daemon.out)"
		cat stl.$i
	done
	f=$(sed -E 's/.*lost forward ([0-9]+), backward ([0-9]+).*/\1/' stl.fwd)
	b=$(sed -E 's/.*lost forward ([0-9]+), backward ([0-9]+).*/\2/' stl.fwd)
	[ "$f" -ge 40 ] || atf_fail "fwd: $f lost forward of some 450"
	[ "$b" -le 2 ] || atf_fail "fwd: $b lost backward, none dropped so"
	f=$(sed -E 's/.*lost forward ([0-9]+), backward ([0-9]+).*/\1/' stl.back)
	b=$(sed -E 's/.*lost forward ([0-9]+), backward ([0-9]+).*/\2/' stl.back)
	[ "$b" -ge 40 ] || atf_fail "back: $b lost backward of some 450"
	[ "$f" -le 2 ] || atf_fail "back: $f lost forward, none dropped so"
	atf_check -o match:'lost forward 0, backward 0 all along' cat stl.clean
	# The round trip's loss, as the console reads it, a fifth each.
	atf_check -o match:'"id":"fwd","address":"198\.18\.62\.2","family":"inet","fib":0,"state":"up"' \
	    -o match:'"id":"back","address":"198\.18\.62\.3","family":"inet","fib":0,"state":"up"' \
	    -o match:'"id":"refused","address":"198\.18\.62\.4","family":"inet","fib":0,"state":"up"' \
	    cat stl.json
	# A refused port: pinged, up all the same; a beacon (kind icmp, as
	# the console says it): never STAMP.
	atf_check -o match:'probe: refused \(198\.18\.62\.4\): its STAMP port refused: pinged until STAMP answers' \
	    cat daemon.out
	atf_check -o not-match:'probe: (refused|bo:gw): stamp' cat daemon.out
	atf_check -o empty "$JGC" -c "$SOCK" sdwan probes '[]'
}
stamp_loss_cleanup()
{
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	[ -f stl.spid ] && kill "$(cat stl.spid)" 2>/dev/null
	jexec $STL_J ipfw -q flush 2>/dev/null
	jexec $STL_J ipfw -q pipe flush 2>/dev/null
	# The epair's end brought home before the jail goes.
	if [ -f stl.epair ]; then
		ep=$(cat stl.epair)
		ifconfig "${ep%a}b" -vnet $STL_J 2>/dev/null
		ifconfig "$ep" destroy 2>/dev/null
	fi
	jail -r $STL_J >/dev/null 2>&1
	true
}

# STAMP's delay each way (PLAN-SDN-YANG 5.1.4): stampd in a vnet jail
# behind an epair, its packets to one address held 50 ms on the way in
# and the replies none.  One host, one clock: the agent's and stampd's
# are the same one, synchronised with each other by construction, which
# --stamp-clock and -C say (the VM's own clock need not be).
STD_J=arc-tsd
STD_NET=198.18.63
# The forward delay within lo and hi ms, the backward under 10.
STD_AWK='{ match($0, /delay forward [0-9.]+ ms, backward [0-9.]+ ms/);
    split(substr($0, RSTART, RLENGTH), v, " ");
    ok = v[3] >= lo && v[3] <= hi && v[6] >= 0 && v[6] < 10;
    print ok ? "ok" : "bad " v[3] " " v[6] }'

# A target's last interval as -d logs it.
std_last()
{
	grep "probe: $1: stamp (stateful reflector): " daemon.out | tail -1
}

# stampd in the jail, its clock as $1 says.
std_stampd()
{
	local i

	: > std.d.out
	jexec $STD_J "$SD" -d -u nobody -r 0 -R 0 -p $P -C "$1" \
	    > std.d.out 2>&1 &
	echo $! > std.spid
	for i in $(seq 1 100); do
		grep -q started std.d.out && break
		sleep 0.05
	done
	grep -q started std.d.out || atf_fail "stampd: $(cat std.d.out)"
}

# The relay in the jail (relay.py), on .3's port in front of stampd.
std_relay()
{
	local i

	: > std.r.out
	jexec $STD_J python3 -I "$(pwd)/relay.py" $STD_NET.3 $P $STD_NET.2 \
	    50 > std.r.out 2>&1 &
	echo $! > std.rpid
	for i in $(seq 1 100); do
		grep -q ready std.r.out && break
		sleep 0.05
	done
	grep -q ready std.r.out || atf_fail "relay: $(cat std.r.out)"
}

atf_test_case stamp_delay cleanup
stamp_delay_head()
{
	atf_set "descr" "Arcana's far ends' delay each way by STAMP: stampd" \
	    "in a vnet jail across an epair, the packets to one address held" \
	    "50 ms on the way in, the replies none (dummynet delay where it" \
	    "is loaded, else a relay in the jail holding them: no ipfw rule" \
	    "delays); both clocks said synchronised within 100 ns (an" \
	    "epair's tens of microseconds told to a tenth), the delay one" \
	    "way, 50 ms forward on the one and next to none" \
	    "backward, none either way on the other; the Timestamp" \
	    "Information TLV filled; a reflector whose error is a second," \
	    "half the round trip, flagged"
	atf_set "require.user" "root"
	atf_set "timeout" "120"
}
stamp_delay_body()
{
	local ep i P

	jls -j $STD_J >/dev/null 2>&1 && atf_skip "a jail $STD_J exists"
	stamp_programs
	P=$(jot -r 1 20000 59999)
	atf_check jail -c name=$STD_J vnet persist path=/ host.hostname=$STD_J
	ep=$(epair_create)
	echo "$ep" > std.epair
	atf_check ifconfig "$ep" inet $STD_NET.1/29 up
	atf_check ifconfig "${ep%a}b" vnet $STD_J
	atf_check jexec $STD_J ifconfig "${ep%a}b" inet $STD_NET.2/29 up
	atf_check jexec $STD_J ifconfig "${ep%a}b" inet $STD_NET.3/32 alias
	std_stampd ptp:0.0000001
	# .3: the way in 50 ms longer; .2: as it is.
	if kldstat -q -m dummynet && kldstat -q -m ipfw; then
		echo "dummynet: pipe 1 delay 50 on the way in to .3"
		atf_check -o ignore jexec $STD_J ipfw pipe 1 config delay 50
		atf_check -o ignore jexec $STD_J ipfw add 100 pipe 1 udp from \
		    any to $STD_NET.3 dst-port $P in
		atf_check -o ignore jexec $STD_J ipfw add 65000 allow ip from \
		    any to any
	else
		# No ipfw-only way to delay: a relay on .3's port, in front
		# of stampd, holds what comes in and sends the replies back
		# at once.  Its own time, both ways, is next to nothing.
		command -v python3 >/dev/null ||
		    atf_skip "neither dummynet(4) nor python3 for a relay"
		echo "dummynet(4) not loaded: a relay in the jail holds the" \
		    "packets to .3 50 ms"
		cat > relay.py <<'EOF'
import collections, select, socket, sys, time
la, port, ra, delay = sys.argv[1], int(sys.argv[2]), sys.argv[3], float(sys.argv[4]) / 1000
i = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
i.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
i.bind((la, port))
o = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
o.connect((ra, port))
print("ready", flush=True)
q = collections.deque()
peer = None
while True:
    now = time.monotonic()
    while q and q[0][0] <= now:
        try:
            o.send(q.popleft()[1])
        except OSError:
            pass
    r, _, _ = select.select([i, o], [], [], max(0, q[0][0] - now) if q else None)
    if i in r:
        d, peer = i.recvfrom(9000)
        q.append((time.monotonic() + delay, d))
    if o in r:
        try:
            d = o.recv(9000)
        except OSError:
            continue
        if peer is not None:
            i.sendto(d, peer)
EOF
		std_relay
	fi
	DAEMON_ARGS="-d --stamp-port $P --stamp-clock ptp:0.0000001" start_daemon
	t='"interval":50,"eval":1000,"timeout":500,"down":10'
	atf_check -o empty "$JGC" -c "$SOCK" sdwan probes \
	    "[{\"id\":\"slow\",\"address\":\"$STD_NET.3\",$t},{\"id\":\"clean\",\"address\":\"$STD_NET.2\",$t}]"
	sleep 5
	# Each target's last interval, as -d logs it (arcana-probe carries
	# none of it yet: 5.1.8): the delay forward and backward, how, and
	# the reflector's Timestamp Information.
	for i in slow clean; do
		std_last $i > std.$i
		[ -s std.$i ] || atf_fail "$i not measured by STAMP: $(cat daemon.out)"
		cat std.$i
	done
	atf_check -o inline:'one way|ptp/sw,ptp/sw\n' \
	    sed -E 's/.* ms \(([^)]*)\); the reflector.s timestamps (.*)/\1|\2/' \
	    std.slow
	atf_check -o inline:'one way|ptp/sw,ptp/sw\n' \
	    sed -E 's/.* ms \(([^)]*)\); the reflector.s timestamps (.*)/\1|\2/' \
	    std.clean
	# 50 ms more forward on the one, next to nothing backward; nothing
	# either way on the other.
	atf_check -o inline:'ok\n' awk -v lo=45 -v hi=80 "$STD_AWK" std.slow
	atf_check -o inline:'ok\n' awk -v lo=0 -v hi=10 "$STD_AWK" std.clean
	# The reflector's error a second: half the round trip, flagged.  Its
	# restart gap makes the agent ping until STAMP answers again (tried
	# every 10 s).  The relay's socket on the port first gone: stampd
	# binds the wildcard address alone.
	if [ -f std.rpid ]; then
		kill "$(cat std.rpid)"
		wait "$(cat std.rpid)" 2>/dev/null
	fi
	kill "$(cat std.spid)"
	wait "$(cat std.spid)" 2>/dev/null
	std_stampd ntp:1
	[ -f std.rpid ] && std_relay
	for i in $(seq 1 250); do
		std_last slow | grep -q 'estimated: half the round trip); the reflector.s timestamps ntp/sw,ntp/sw$' &&
		    break
		sleep 0.1
	done
	std_last slow > std.slow
	cat std.slow
	atf_check -o match:'\(estimated: half the round trip\); the reflector.s timestamps ntp/sw,ntp/sw$' \
	    cat std.slow
	# Half the round trip each way: 25 ms and a little, the same.
	atf_check -o inline:'ok\n' awk '{ match($0, /delay forward [0-9.]+ ms, backward [0-9.]+ ms/);
	    split(substr($0, RSTART, RLENGTH), v, " ");
	    ok = v[3] == v[6] && v[3] >= 20 && v[3] <= 45;
	    print ok ? "ok" : "bad " v[3] " " v[6] }' std.slow
	atf_check -o empty "$JGC" -c "$SOCK" sdwan probes '[]'
}
stamp_delay_cleanup()
{
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	[ -f std.spid ] && kill "$(cat std.spid)" 2>/dev/null
	[ -f std.rpid ] && kill "$(cat std.rpid)" 2>/dev/null
	jexec $STD_J ipfw -q flush 2>/dev/null
	jexec $STD_J ipfw -q pipe flush 2>/dev/null
	# The epair's end brought home before the jail goes.
	if [ -f std.epair ]; then
		ep=$(cat std.epair)
		ifconfig "${ep%a}b" -vnet $STD_J 2>/dev/null
		ifconfig "$ep" destroy 2>/dev/null
	fi
	jail -r $STD_J >/dev/null 2>&1
	true
}

# STAMP's DSCP each way (PLAN-SDN-YANG 5.1.5): stampd in a vnet jail
# behind an epair, refusing DSCP 34; the jail's ipfw bleaching the DSCP
# of what comes in to one of its two addresses.
STC_J=arc-tsc
STC_NET=198.18.64

# A target's last "stamp path" line, as -d logs it.
stc_last()
{
	grep "probe: $1: stamp path: " daemon.out | tail -1
}

atf_test_case stamp_cos cleanup
stamp_cos_head()
{
	atf_set "descr" "Arcana's far ends' DSCP each way by STAMP's Class" \
	    "of Service TLV: stampd in a vnet jail across an epair refusing" \
	    "DSCP 34, the jail's ipfw setting DSCP 0 on what comes in to one" \
	    "address; DSCP 46 there and back on the other (tcpdump -v sees" \
	    "tos 0xb8 each way, where bpf is), 0 forward and 46 back through" \
	    "the bleaching," \
	    "34 refused: the reply with what came, RP"
	atf_set "require.user" "root"
	atf_set "timeout" "120"
}
stamp_cos_body()
{
	local ep i P t

	kldstat -q -m ipfw || atf_skip "ipfw(4) is not loaded"
	jls -j $STC_J >/dev/null 2>&1 && atf_skip "a jail $STC_J exists"
	stamp_programs
	P=$(jot -r 1 20000 59999)
	atf_check jail -c name=$STC_J vnet persist path=/ host.hostname=$STC_J
	ep=$(epair_create)
	echo "$ep" > stc.epair
	atf_check ifconfig "$ep" inet $STC_NET.1/29 up
	atf_check ifconfig "${ep%a}b" vnet $STC_J
	atf_check jexec $STC_J ifconfig "${ep%a}b" inet $STC_NET.2/29 up
	atf_check jexec $STC_J ifconfig "${ep%a}b" inet $STC_NET.3/32 alias
	# The jail's own ruleset: what comes in to .3 its DSCP 0, the rest
	# let by.
	atf_check -o ignore jexec $STC_J ipfw add 100 setdscp 0 udp from any \
	    to $STC_NET.3 dst-port $P in
	atf_check -o ignore jexec $STC_J ipfw add 65000 allow ip from any to any
	jexec $STC_J "$SD" -d -u nobody -r 0 -R 0 -p $P -D 34 > stc.d.out 2>&1 &
	echo $! > stc.spid
	for i in $(seq 1 100); do
		grep -q started stc.d.out && break
		sleep 0.05
	done
	grep -q started stc.d.out || atf_fail "stampd: $(cat stc.d.out)"
	# What the wire carries to and from .2, both ways, where bpf(4) is
	# (not in a jail without its devices, as the lab's: there the DSCP
	# each way is the reflector's DSCP2 and the reply's IP_RECVTOS).
	if command -v tcpdump >/dev/null && tcpdump -D >/dev/null 2>&1; then
		tcpdump -l -n -t -v -i "$ep" -c 40 udp and host $STC_NET.2 \
		    > stc.tcpdump 2>stc.tcpdump.err &
		echo $! > stc.tpid
		sleep 1
	fi
	DAEMON_ARGS="-d --stamp-port $P" start_daemon
	t='"interval":50,"eval":1000,"timeout":500,"down":10'
	atf_check -o empty "$JGC" -c "$SOCK" sdwan probes \
	    "[{\"id\":\"ef\",\"address\":\"$STC_NET.2\",\"dscp\":46,$t},{\"id\":\"bleached\",\"address\":\"$STC_NET.3\",\"dscp\":46,$t},{\"id\":\"refused\",\"address\":\"$STC_NET.2\",\"dscp\":34,$t},{\"id\":\"refused0\",\"address\":\"$STC_NET.3\",\"dscp\":34,$t}]"
	sleep 3
	for i in ef bleached refused refused0; do
		stc_last $i > stc.$i
		[ -s stc.$i ] || atf_fail "$i not measured by STAMP: $(cat daemon.out)"
		cat stc.$i
	done
	atf_check -o match:': stamp path: dscp 46 sent, forward 46, backward 46; ' \
	    cat stc.ef
	atf_check -o match:': stamp path: dscp 46 sent, forward 0, backward 46; ' \
	    cat stc.bleached
	atf_check -o match:': stamp path: dscp 34 sent, forward 34, backward 34 \(the reflector refused it\); ' \
	    cat stc.refused
	atf_check -o match:': stamp path: dscp 34 sent, forward 0, backward 0 \(the reflector refused it\); ' \
	    cat stc.refused0
	# The wire: tos 0xb8 (DSCP 46) and 0x88 (34) out to .2 and back.
	if [ -f stc.tpid ]; then
		for i in $(seq 1 50); do
			kill -0 "$(cat stc.tpid)" 2>/dev/null || break
			sleep 0.1
		done
		kill "$(cat stc.tpid)" 2>/dev/null
		head -8 stc.tcpdump
		# -v's header line, then the addresses on the next.
		awk -v n=$STC_NET -v p=$P '
		    /^IP \(tos / { tos = $3; sub(/,$/, "", tos); next }
		    index($1, n ".1.") == 1 && $3 == n ".2." p ":" { o[tos]++ }
		    $1 == n ".2." p && index($3, n ".1.") == 1 { b[tos]++ }
		    END { print (o["0xb8"] > 0 ? "out" : "-") " " \
			(b["0xb8"] > 0 ? "back" : "-") " " \
			(o["0x88"] > 0 ? "out34" : "-") " " \
			(b["0x88"] > 0 ? "back34" : "-") }' stc.tcpdump > stc.wire
		atf_check -o inline:'out back out34 back34\n' cat stc.wire
	fi
	atf_check -o empty "$JGC" -c "$SOCK" sdwan probes '[]'
}
stamp_cos_cleanup()
{
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	[ -f stc.spid ] && kill "$(cat stc.spid)" 2>/dev/null
	[ -f stc.tpid ] && kill "$(cat stc.tpid)" 2>/dev/null
	jexec $STC_J ipfw -q flush 2>/dev/null
	# The epair's end brought home before the jail goes.
	if [ -f stc.epair ]; then
		ep=$(cat stc.epair)
		ifconfig "${ep%a}b" -vnet $STC_J 2>/dev/null
		ifconfig "$ep" destroy 2>/dev/null
	fi
	jail -r $STC_J >/dev/null 2>&1
	true
}

# STAMP's Location and Direct Measurement TLVs (PLAN-SDN-YANG 5.1.6):
# stampd in a vnet jail behind an epair; one address reached directly,
# a fifth of what comes in to it lost, the other through a relay in the
# jail that rewrites the source (and the destination) as a NAT does.
STN_J=arc-tsn
STN_NET=198.18.65

# A target's last "stamp path" line, and its last interval's, as -d
# logs them.
stn_path()
{
	grep "probe: $1: stamp path: " daemon.out | tail -1
}
stn_last()
{
	grep "probe: $1: stamp (stateful reflector): " daemon.out | tail -1
}
# The stateful line of the round whose path line is the last: the two
# written one after the other, read together so neither is a round on.
stn_pair()
{
	awk -v s="probe: $1: stamp (stateful reflector): " \
	    -v p="probe: $1: stamp path: " \
	    'index($0, s) { l = $0 } index($0, p) { print l > "stn.pair.last"; print $0 > "stn.pair.path"; close("stn.pair.last"); close("stn.pair.path") }' \
	    daemon.out
}

atf_test_case stamp_location cleanup
stamp_location_head()
{
	atf_set "descr" "Arcana's far ends' view of the probes by STAMP's" \
	    "Location TLV and the loss each way by its Direct Measurement" \
	    "TLV: stampd in a vnet jail across an epair, one address" \
	    "reached directly, a fifth of what comes in to it denied by the" \
	    "jail's ipfw (prob), the other through a relay in the jail that" \
	    "sends on from its own address and port: no NAT and the agent's" \
	    "own address and port seen on the one, the loss forward by the" \
	    "counters as by the sequence; a NAT, the source and destination" \
	    "rewritten, on the other"
	atf_set "require.user" "root"
	atf_set "timeout" "120"
}
stamp_location_body()
{
	local ep i P t f b cf cb d

	kldstat -q -m ipfw || atf_skip "ipfw(4) is not loaded"
	command -v python3 >/dev/null || atf_skip "no python3 for the relay"
	jls -j $STN_J >/dev/null 2>&1 && atf_skip "a jail $STN_J exists"
	stamp_programs
	P=$(jot -r 1 20000 59999)
	atf_check jail -c name=$STN_J vnet persist path=/ host.hostname=$STN_J
	ep=$(epair_create)
	echo "$ep" > stn.epair
	atf_check ifconfig "$ep" inet $STN_NET.1/29 up
	atf_check ifconfig "${ep%a}b" vnet $STN_J
	atf_check jexec $STN_J ifconfig "${ep%a}b" inet $STN_NET.2/29 up
	atf_check jexec $STN_J ifconfig "${ep%a}b" inet $STN_NET.3/32 alias
	# The jail's own ruleset: a fifth of what comes in to .2 denied.
	atf_check -o ignore jexec $STN_J ipfw add 100 prob 0.2 deny udp from \
	    $STN_NET.1 to $STN_NET.2 dst-port $P in
	atf_check -o ignore jexec $STN_J ipfw add 65000 allow ip from any to any
	jexec $STN_J "$SD" -d -u nobody -r 0 -R 0 -p $P > stn.d.out 2>&1 &
	echo $! > stn.spid
	for i in $(seq 1 100); do
		grep -q started stn.d.out && break
		sleep 0.05
	done
	grep -q started stn.d.out || atf_fail "stampd: $(cat stn.d.out)"
	# The relay on .3's port: on to stampd at .2 from a socket of its
	# own, the replies back to whoever sent last.
	cat > relay.py <<'EOF'
import select, socket, sys
la, port, ra = sys.argv[1], int(sys.argv[2]), sys.argv[3]
i = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
i.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
i.bind((la, port))
o = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
o.connect((ra, port))
print("ready", flush=True)
peer = None
while True:
    r, _, _ = select.select([i, o], [], [])
    if i in r:
        d, peer = i.recvfrom(9000)
        try:
            o.send(d)
        except OSError:
            pass
    if o in r:
        try:
            d = o.recv(9000)
        except OSError:
            continue
        if peer is not None:
            i.sendto(d, peer)
EOF
	jexec $STN_J python3 -I "$(pwd)/relay.py" $STN_NET.3 $P $STN_NET.2 \
	    > stn.r.out 2>&1 &
	echo $! > stn.rpid
	for i in $(seq 1 100); do
		grep -q ready stn.r.out && break
		sleep 0.05
	done
	grep -q ready stn.r.out || atf_fail "relay: $(cat stn.r.out)"
	DAEMON_ARGS="-d --stamp-port $P" start_daemon
	t='"interval":20,"eval":1000,"timeout":300,"down":10'
	atf_check -o empty "$JGC" -c "$SOCK" sdwan probes \
	    "[{\"id\":\"direct\",\"address\":\"$STN_NET.2\",$t},{\"id\":\"natted\",\"address\":\"$STN_NET.3\",$t}]"
	sleep 8
	for i in direct natted; do
		stn_path $i > stn.$i
		stn_last $i > stn.$i.last
		[ -s stn.$i ] || atf_fail "$i not measured by STAMP: $(cat daemon.out)"
		cat stn.$i stn.$i.last
	done
	# Direct: its own address seen, no NAT.
	atf_check -o match:"; seen from $STN_NET\.1 port [0-9]+ to $STN_NET\.2 port $P \(no NAT\); " \
	    cat stn.direct
	# Through the relay: from the relay's address and port, to stampd's.
	atf_check -o match:"; seen from $STN_NET\.2 port [0-9]+ to $STN_NET\.2 port $P \(NAT: both rewritten\); " \
	    cat stn.natted
	# The loss forward by the counters, as by the stateful sequence, of
	# one round; none back.  The sequence counts a loss once every
	# earlier probe is answered or timed out, the counters at a reply:
	# they may differ by what is in flight, a timeout's probes (300 / 20).
	stn_pair direct
	f=$(sed -E 's/.*lost forward ([0-9]+), backward ([0-9]+) all along.*/\1/' stn.pair.last)
	b=$(sed -E 's/.*lost forward ([0-9]+), backward ([0-9]+) all along.*/\2/' stn.pair.last)
	cf=$(sed -E 's/.*lost by counters forward ([0-9]+), backward ([0-9]+) all along$/\1/' stn.pair.path)
	cb=$(sed -E 's/.*lost by counters forward ([0-9]+), backward ([0-9]+) all along$/\2/' stn.pair.path)
	echo "sequence $f/$b, counters $cf/$cb"
	[ "$cf" -ge 30 ] || atf_fail "direct: $cf lost forward by counters of some 400"
	[ "$cb" -le 2 ] || atf_fail "direct: $cb lost backward by counters, none dropped so"
	d=$((cf - f))
	[ "${d#-}" -le 15 ] || atf_fail "direct: $cf forward by counters, $f by the sequence"
	atf_check -o match:'lost by counters forward 0, backward 0 all along$' \
	    cat stn.natted
	atf_check -o empty "$JGC" -c "$SOCK" sdwan probes '[]'
}
stamp_location_cleanup()
{
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	[ -f stn.spid ] && kill "$(cat stn.spid)" 2>/dev/null
	[ -f stn.rpid ] && kill "$(cat stn.rpid)" 2>/dev/null
	jexec $STN_J ipfw -q flush 2>/dev/null
	# The epair's end brought home before the jail goes.
	if [ -f stn.epair ]; then
		ep=$(cat stn.epair)
		ifconfig "${ep%a}b" -vnet $STN_J 2>/dev/null
		ifconfig "$ep" destroy 2>/dev/null
	fi
	jail -r $STN_J >/dev/null 2>&1
	true
}

# STAMP's authenticated mode (PLAN-SDN-YANG 5.1.7): stampd in a vnet
# jail behind an epair under the key a plain tunnel's two ends derive,
# the far end's made here as its agent would make it.
STA_J=arc-tsa
STA_NET=198.18.66

# The STAMP key of a tunnel end whose pair is $1 (a PEM file) and whose
# far end's public half is $2: "ssid key", as the agent derives it (an
# X25519 agreement, HKDF-SHA256 salted "arcana stamp v1", both halves
# in order and a zero epoch the info; 32 octets of key, 2 of SSID).
sta_derive()
{
	cat > derive.py <<'EOF'
import base64, hashlib, hmac, os, subprocess, sys, tempfile
pem, peer = sys.argv[1], base64.b64decode(sys.argv[2])
der = subprocess.run(["openssl", "pkey", "-in", pem, "-pubout", "-outform",
    "DER"], check=True, capture_output=True).stdout
mine = der[-32:]
spki = bytes.fromhex("302a300506032b656e032100") + peer
fd, path = tempfile.mkstemp(dir=".")
os.write(fd, b"-----BEGIN PUBLIC KEY-----\n" + base64.encodebytes(spki) +
    b"-----END PUBLIC KEY-----\n")
os.close(fd)
shared = subprocess.run(["openssl", "pkeyutl", "-derive", "-inkey", pem,
    "-peerkey", path], check=True, capture_output=True).stdout
os.unlink(path)
info = min(mine, peer) + max(mine, peer) + bytes(4)
prk = hmac.new(b"arcana stamp v1", shared, hashlib.sha256).digest()
okm, t, i = b"", b"", 1
while len(okm) < 34:
    t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
    okm += t
    i += 1
ssid = okm[32] << 8 | okm[33]
print("%d %s" % (ssid or 1, okm[:32].hex()))
EOF
	python3 -I derive.py "$1" "$2"
}

# A pair made as the far end's agent would: its PEM and its public half.
sta_pair()
{
	(umask 077; openssl genpkey -algorithm X25519 -out "$1.pem" 2>/dev/null)
	openssl pkey -in "$1.pem" -pubout -outform DER | tail -c 32 |
	    openssl base64 -A > "$1.pub"
}

atf_test_case stamp_auth cleanup
stamp_auth_head()
{
	atf_set "descr" "A plain tunnel's STAMP authenticated: the agent's key" \
	    "and SSID derived from its tunnel end's pair and the far end's" \
	    "public half, the same as the far end derives, its stampd key" \
	    "file 0600 with it; stampd in a vnet jail under that key" \
	    "answers; through a relay flipping one octet of each probe" \
	    "nothing is answered, stampd counting the failures, and the" \
	    "agent falls back to ICMP; a far end of another key is refused" \
	    "the same; no key in a log"
	atf_set "require.user" "root"
	atf_set "timeout" "120"
}
stamp_auth_body()
{
	local ep i P t A K far1 far2 k

	command -v python3 >/dev/null || atf_skip "no python3 for the relay"
	command -v openssl >/dev/null || atf_skip "no openssl(1) for the far end"
	jls -j $STA_J >/dev/null 2>&1 && atf_skip "a jail $STA_J exists"
	umask 077
	stamp_programs
	P=$(jot -r 1 20000 59999)
	atf_check jail -c name=$STA_J vnet persist path=/ host.hostname=$STA_J
	ep=$(epair_create)
	echo "$ep" > sta.epair
	atf_check ifconfig "$ep" inet $STA_NET.1/29 up
	atf_check ifconfig "${ep%a}b" vnet $STA_J
	atf_check jexec $STA_J ifconfig "${ep%a}b" inet $STA_NET.2/29 up
	for i in 3 4; do
		atf_check jexec $STA_J ifconfig "${ep%a}b" inet $STA_NET.$i/32 \
		    alias
	done
	# The agent: stampd's script in its rc.d, service(8) a log, a root
	# whose rc.conf reads Arcana's file; its stampd key file there.
	mkdir -p root/etc/defaults root/usr/local/etc rc.d
	cp /etc/defaults/rc.conf root/etc/defaults/
	printf 'rc_conf_files="/etc/rc.conf /etc/rc.conf.local /usr/local/etc/rc.conf.d/arcana"\n' \
	    > root/etc/rc.conf
	printf '#!/bin/sh\n' > rc.d/stampd
	chmod +x rc.d/stampd
	printf '#!/bin/sh\necho "$*" >> %s/service.log\n' "$(pwd)" \
	    > fake-service
	chmod +x fake-service
	DAEMON_ARGS="-d --stamp-port $P --root $(pwd)/root -R $(pwd)/rc.d -s $(pwd)/fake-service" \
	    start_daemon
	# This end's pair, as the console has it made (ipsec-sa key).
	atf_check -o save:sta.key "$JGC" -t -c "$SOCK" ipsec-sa key gre9
	A=$(sed -nE 's/.*public ([A-Za-z0-9+/]{43}=).*/\1/p' sta.key | head -1)
	[ -n "$A" ] || atf_fail "no public half: $(cat sta.key)"
	# Two far ends: the jail's, and another.
	sta_pair far1
	sta_pair far2
	far1=$(cat far1.pub)
	far2=$(cat far2.pub)
	K=$(sta_derive far1.pem "$A")
	printf '%s\n' "$K" > sta.keys
	jexec $STA_J "$SD" -d -u nobody -r 0 -R 0 -p $P -K "$(pwd)/sta.keys" \
	    > sta.d.out 2>&1 &
	echo $! > sta.spid
	for i in $(seq 1 100); do
		grep -q started sta.d.out && break
		sleep 0.05
	done
	grep -q 'started: .*, 1 key, ' sta.d.out || atf_fail "stampd: $(cat sta.d.out)"
	# The relay on .3's port: on to stampd at .2, the 21st octet of each
	# probe flipped (its timestamp), the replies back as they are.
	cat > relay.py <<'EOF'
import select, socket, sys
la, port, ra = sys.argv[1], int(sys.argv[2]), sys.argv[3]
i = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
i.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
i.bind((la, port))
o = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
o.connect((ra, port))
print("ready", flush=True)
peer = None
while True:
    r, _, _ = select.select([i, o], [], [])
    if i in r:
        d, peer = i.recvfrom(9000)
        d = bytearray(d)
        if len(d) > 20:
            d[20] ^= 0x01
        try:
            o.send(bytes(d))
        except OSError:
            pass
    if o in r:
        try:
            d = o.recv(9000)
        except OSError:
            continue
        if peer is not None:
            i.sendto(d, peer)
EOF
	jexec $STA_J python3 -I "$(pwd)/relay.py" $STA_NET.3 $P $STA_NET.2 \
	    > sta.r.out 2>&1 &
	echo $! > sta.rpid
	for i in $(seq 1 100); do
		grep -q ready sta.r.out && break
		sleep 0.05
	done
	grep -q ready sta.r.out || atf_fail "relay: $(cat sta.r.out)"
	t='"interval":20,"eval":1000,"timeout":300,"down":10,"stamp_interface":"gre9"'
	atf_check -o empty "$JGC" -c "$SOCK" sdwan probes \
	    "[{\"id\":\"good\",\"address\":\"$STA_NET.2\",$t,\"stamp_peer\":\"$far1\"},{\"id\":\"flip\",\"address\":\"$STA_NET.3\",$t,\"stamp_peer\":\"$far1\"},{\"id\":\"wrong\",\"address\":\"$STA_NET.4\",$t,\"stamp_peer\":\"$far2\"}]"
	sleep 8
	atf_check -o save:sta.json "$JGC" -c "$SOCK" sdwan
	# Authenticated, answered: measured by STAMP.
	grep "probe: good: stamp (stateful reflector): " daemon.out | tail -1 \
	    > sta.good
	[ -s sta.good ] || atf_fail "good not measured by STAMP: $(cat daemon.out)"
	cat sta.good
	atf_check -o match:"probe: good: stamp authenticated \(SSID ${K%% *}\); replies failing authentication 0 all along" \
	    cat daemon.out
	atf_check -o match:'"id":"good","address":"198\.18\.66\.2","family":"inet","fib":0,"state":"up"' \
	    cat sta.json
	# Flipped on the way: never answered, counted by stampd; pinged.
	atf_check -o match:'probe: flip \(198\.18\.66\.3\): no STAMP reply in 10 probes: pinged until STAMP answers' \
	    -o match:'probe: wrong \(198\.18\.66\.4\): no STAMP reply in 10 probes: pinged until STAMP answers' \
	    cat daemon.out
	atf_check -o match:'"id":"flip","address":"198\.18\.66\.3","family":"inet","fib":0,"state":"up"' \
	    -o match:'"id":"wrong","address":"198\.18\.66\.4","family":"inet","fib":0,"state":"up"' \
	    cat sta.json
	atf_check -o not-match:'probe: (flip|wrong): stamp \(' cat daemon.out
	n=$(sed -nE 's/.* ([0-9]+) requests failing authentication dropped/\1/p' \
	    sta.d.out | tail -1)
	echo "stampd: ${n:-no} requests failing authentication dropped"
	[ "${n:-0}" -ge 20 ] || atf_fail "stampd counted ${n:-none}: $(cat sta.d.out)"
	# The agent's stampd key file: root's, 0600, the jail's key in it
	# (both ends derived the same), the other far end's beside it.
	k=root/usr/local/etc/stampd.keys
	wait_for "grep -Eq '^stampd (restart|reload)\$' service.log"
	atf_check -o match:'^stampd (restart|reload)$' cat service.log
	atf_check -o inline:'-rw------- root\n' stat -f '%Sp %Su' $k
	atf_check -o match:"^$K\$" cat $k
	atf_check -o match:'^# arcana-agent: ' cat $k
	atf_check -o inline:'2\n' grep -c '^[0-9]* [0-9a-f]\{64\}$' $k
	# No key in a log.
	atf_check -s exit:1 grep -F -e "${K#* }" daemon.out sta.d.out sta.json
	atf_check -o empty "$JGC" -c "$SOCK" sdwan probes '[]'
	# Its targets gone: Arcana's keys taken out of the file.
	wait_for "grep -q '^stampd onestop\$' service.log"
	atf_check -o match:'^stampd onestop$' cat service.log
	atf_check -s exit:1 -o inline:'0\n' grep -c '[0-9a-f]\{64\}' $k
}
stamp_auth_cleanup()
{
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	[ -f sta.spid ] && kill "$(cat sta.spid)" 2>/dev/null
	[ -f sta.rpid ] && kill "$(cat sta.rpid)" 2>/dev/null
	# The epair's end brought home before the jail goes.
	if [ -f sta.epair ]; then
		ep=$(cat sta.epair)
		ifconfig "${ep%a}b" -vnet $STA_J 2>/dev/null
		ifconfig "$ep" destroy 2>/dev/null
	fi
	jail -r $STA_J >/dev/null 2>&1
	true
}

atf_test_case stamp_unauthenticated cleanup
stamp_unauthenticated_head()
{
	atf_set "descr" "A plain tunnel's authenticated STAMP fallen back to" \
	    "ICMP echo raises arcana-alarms' stamp-unauthenticated: stampd" \
	    "on the loopback under the key both ends derive, stopped as one" \
	    "on the path dropping the packets would make it; the target" \
	    "pinged and up, the alarm Warning with why, its sdwan-fault" \
	    "event, the session icmp with its key; stampd back, the next" \
	    "try answered and the alarm cleared"
	atf_set "require.user" "root"
	atf_set "timeout" "120"
}
stamp_unauthenticated_body()
{
	local i P A K far t

	command -v python3 >/dev/null || atf_skip "no python3 for the far key"
	command -v openssl >/dev/null || atf_skip "no openssl(1) for the far end"
	umask 077
	stamp_programs
	P=$(jot -r 1 20000 59999)
	mkdir -p root/etc/defaults root/usr/local/etc rc.d
	cp /etc/defaults/rc.conf root/etc/defaults/
	printf 'rc_conf_files="/etc/rc.conf /etc/rc.conf.local /usr/local/etc/rc.conf.d/arcana"\n' \
	    > root/etc/rc.conf
	printf '#!/bin/sh\n' > rc.d/stampd
	chmod +x rc.d/stampd
	printf '#!/bin/sh\necho "$*" >> %s/service.log\n' "$(pwd)" \
	    > fake-service
	chmod +x fake-service
	DAEMON_ARGS="-d --stamp-port $P --root $(pwd)/root -R $(pwd)/rc.d -s $(pwd)/fake-service" \
	    start_daemon
	atf_check -o save:ua.key "$JGC" -t -c "$SOCK" ipsec-sa key gre9
	A=$(sed -nE 's/.*public ([A-Za-z0-9+/]{43}=).*/\1/p' ua.key | head -1)
	[ -n "$A" ] || atf_fail "no public half: $(cat ua.key)"
	sta_pair far
	far=$(cat far.pub)
	K=$(sta_derive far.pem "$A")
	printf '%s\n' "$K" > ua.keys
	"$SD" -d -u nobody -r 0 -R 0 -p $P -K "$(pwd)/ua.keys" > ua.d.out 2>&1 &
	echo $! > ua.spid
	for i in $(seq 1 100); do
		grep -q started ua.d.out && break
		sleep 0.05
	done
	grep -q 'started: .*, 1 key, ' ua.d.out || atf_fail "stampd: $(cat ua.d.out)"
	t='"interval":20,"eval":1000,"timeout":300,"down":5,"stamp_interface":"gre9"'
	atf_check -o empty "$JGC" -c "$SOCK" sdwan probes \
	    "[{\"id\":\"t\",\"address\":\"127.0.0.1\",$t,\"stamp_peer\":\"$far\"}]"
	for i in $(seq 1 300); do
		grep -q 'probe: t: stamp authenticated' daemon.out && break
		sleep 0.1
	done
	atf_check -o match:'probe: t: stamp authenticated \(SSID [0-9]+\)' \
	    cat daemon.out
	atf_check -o not-match:'"alarm-text":"[^"]*","alarm-type-id":"arcana-alarms:stamp-unauthenticated"' \
	    "$JGC" -c "$SOCK" get alarms
	# Silent, as dropped on the way: pinged, measured unauthenticated.
	kill -STOP "$(cat ua.spid)"
	for i in $(seq 1 300); do
		grep -q 'fault stamp-unauthenticated' daemon.out && break
		sleep 0.1
	done
	atf_check -o match:'probe: t \(127\.0\.0\.1\): no STAMP reply in 5 probes: pinged until STAMP answers' \
	    -o match:'fault stamp-unauthenticated \(Warning\) t: authenticated STAMP to 127\.0\.0\.1 in FIB 0 fell back to ICMP echo, unauthenticated: no STAMP reply in 5 probes' \
	    cat daemon.out
	atf_check -o save:ua.json "$JGC" -c "$SOCK" sdwan
	atf_check -o match:'"type":"stamp-unauthenticated","severity":"Warning","was":"Warning","object":"t","by":"probe","description":"authenticated STAMP to 127\.0\.0\.1 in FIB 0 fell back to ICMP echo, unauthenticated: no STAMP reply in 5 probes","cleared":false' \
	    -o match:'"id":"t","address":"127\.0\.0\.1","family":"inet","fib":0,"state":"up"' \
	    -o not-match:'"type":"tunnel"' cat ua.json
	atf_check -o match:'"alarm-type-id":"arcana-alarms:stamp-unauthenticated"' \
	    -o match:'"perceived-severity":"warning"' "$JGC" -c "$SOCK" get alarms
	atf_check -o match:'"kind":"sdwan-fault","data":\{"type":"stamp-unauthenticated","severity":"Warning"' \
	    "$JGC" -c "$SOCK" events
	# Its session: by ICMP, its key kept, why.
	atf_check -o match:'"method":"icmp"' -o match:'"authenticated":true' \
	    -o match:'"reason":"no STAMP reply in 5 probes"' \
	    "$JGC" -c "$SOCK" get stamp
	# stampd back: the next try (10 s at most) answered, cleared.
	kill -CONT "$(cat ua.spid)"
	for i in $(seq 1 300); do
		grep -q 'fault stamp-unauthenticated t cleared' daemon.out && break
		sleep 0.1
	done
	atf_check -o match:'probe: t \(127\.0\.0\.1\): STAMP answers again' \
	    -o match:'fault stamp-unauthenticated t cleared: authenticated STAMP from 127\.0\.0\.1 answers again' \
	    cat daemon.out
	atf_check -o match:'"type":"stamp-unauthenticated","severity":"Cleared","was":"Warning","object":"t"[^}]*"cleared":true' \
	    "$JGC" -c "$SOCK" sdwan
	atf_check -o match:'"kind":"sdwan-fault","data":\{"type":"stamp-unauthenticated","severity":"Cleared"' \
	    "$JGC" -c "$SOCK" events
	atf_check -o match:'"method":"stamp"' "$JGC" -c "$SOCK" get stamp
	# No key in a log.
	atf_check -s exit:1 grep -F -e "${K#* }" daemon.out ua.d.out
	atf_check -o empty "$JGC" -c "$SOCK" sdwan probes '[]'
}
stamp_unauthenticated_cleanup()
{
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	if [ -f ua.spid ]; then
		kill -CONT "$(cat ua.spid)" 2>/dev/null
		kill "$(cat ua.spid)" 2>/dev/null
	fi
	true
}

# Both kinds in one service (PLAN-SDN-YANG 5.1.8): stampd in a vnet jail
# behind an epair, three addresses on its end, each a target of the same
# service's table: one of kind stamp, one of kind icmp, one auto whose
# STAMP port is refused.
STK_J=arc-tsk
STK_NET=198.18.67

atf_test_case stamp_kinds cleanup
stamp_kinds_head()
{
	atf_set "descr" "Both kinds in one service: stampd in a vnet jail" \
	    "across an epair; a target of kind stamp measured by STAMP" \
	    "(arcana-stamp's session: stateful, the DSCP each way, no NAT), one" \
	    "of kind icmp pinged and never STAMP, no session, an auto one" \
	    "whose STAMP port is refused fallen back to ICMP, why said; all up;" \
	    "STAMP to the first denied, it goes down though it answers echoes" \
	    "(no fallback), the others up"
	atf_set "require.user" "root"
	atf_set "timeout" "120"
}
stamp_kinds_body()
{
	local ep i P

	kldstat -q -m ipfw || atf_skip "ipfw(4) is not loaded"
	[ "$(sysctl -n net.inet.ip.fw.default_to_accept)" = 1 ] ||
	    atf_skip "net.inet.ip.fw.default_to_accept is not 1"
	jls -j $STK_J >/dev/null 2>&1 && atf_skip "a jail $STK_J exists"
	stamp_programs
	P=$(jot -r 1 20000 59999)
	atf_check jail -c name=$STK_J vnet persist path=/ host.hostname=$STK_J
	ep=$(epair_create)
	echo "$ep" > stk.epair
	atf_check ifconfig "$ep" inet $STK_NET.1/29 up
	atf_check ifconfig "${ep%a}b" vnet $STK_J
	atf_check jexec $STK_J ifconfig "${ep%a}b" inet $STK_NET.2/29 up
	for i in 3 4; do
		atf_check jexec $STK_J ifconfig "${ep%a}b" inet $STK_NET.$i/32 \
		    alias
	done
	jexec $STK_J "$SD" -d -u nobody -r 0 -R 0 -p $P > stk.d.out 2>&1 &
	echo $! > stk.spid
	for i in $(seq 1 100); do
		grep -q started stk.d.out && break
		sleep 0.05
	done
	grep -q started stk.d.out || atf_fail "stampd: $(cat stk.d.out)"
	# .4: its STAMP port refused.
	atf_check -o ignore jexec $STK_J ipfw add 120 unreach port udp from \
	    any to $STK_NET.4 dst-port $P in
	DAEMON_ARGS="-d --stamp-port $P" start_daemon
	t='"interval":20,"eval":1000,"timeout":300,"down":5,"dscp":46'
	atf_check -o empty "$JGC" -c "$SOCK" sdwan probes \
	    "[{\"id\":\"svc/a-b\",\"address\":\"$STK_NET.2\",\"kind\":\"stamp\",$t},{\"id\":\"svc/a-c\",\"address\":\"$STK_NET.3\",\"kind\":\"icmp\",$t},{\"id\":\"svc/a-d\",\"address\":\"$STK_NET.4\",$t}]"
	sleep 4
	# Each as its kind says: STAMP, an echo, STAMP fallen back.
	atf_check -o save:stk.txt "$JGC" -c "$SOCK" sdwan stamp
	cat stk.txt
	atf_check -o match:'^svc/a-b: stamp \(stateful, stamp alone\), rtt [0-9.]+ ms, .*lost forward 0, backward 0 of [1-9][0-9]*, dscp 46>46>46, NAT none, auth no$' \
	    -o match:'^svc/a-d: icmp \(unknown\) because its STAMP port refused' \
	    -o not-match:'^svc/a-c' cat stk.txt
	atf_check -o save:stk.json "$JGC" -c "$SOCK" sdwan
	atf_check -o match:'"id":"svc/a-b","address":"198\.18\.67\.2","family":"inet","fib":0,"state":"up"' \
	    -o match:'"id":"svc/a-c","address":"198\.18\.67\.3","family":"inet","fib":0,"state":"up"' \
	    -o match:'"id":"svc/a-d","address":"198\.18\.67\.4","family":"inet","fib":0,"state":"up"' \
	    -o match:'"stamp":\{"target":"svc/a-b","kind":"stamp","method":"stamp"' \
	    -o match:'"stamp":\{"target":"svc/a-d","kind":"auto","method":"icmp","reason":"its STAMP port refused"' \
	    cat stk.json
	atf_check -o match:'"target":"svc/a-d"' \
	    -o match:'"fallbacks":"1","late":"[0-9]+","lost":"[0-9]+","lost-backward":"[0-9]+","lost-forward":"[0-9]+","lost-unknown":"[0-9]+","received":"0","refused":"[1-9][0-9]*"' \
	    -o not-match:'"target":"svc/a-c"' "$JGC" -c "$SOCK" get stamp
	atf_check -o not-match:'probe: svc/a-c: stamp' cat daemon.out
	grep -q 'probe: svc/a-b: stamp (stateful reflector): ' daemon.out ||
	    atf_fail "svc/a-b not measured by STAMP: $(cat daemon.out)"
	# STAMP to the first denied: down, though it answers echoes; no
	# fallback, why said.
	atf_check -o ignore jexec $STK_J ipfw add 100 deny udp from any to \
	    $STK_NET.2 dst-port $P in
	atf_check -o ignore ping -c 1 -t 2 $STK_NET.2
	for i in $(seq 1 100); do
		"$JGC" -c "$SOCK" sdwan | grep -q '"id":"svc/a-b","address":"198\.18\.67\.2","family":"inet","fib":0,"state":"down"' && break
		sleep 0.1
	done
	atf_check -o match:'"id":"svc/a-b","address":"198\.18\.67\.2","family":"inet","fib":0,"state":"down"' \
	    -o match:'"id":"svc/a-c","address":"198\.18\.67\.3","family":"inet","fib":0,"state":"up"' \
	    -o match:'"id":"svc/a-d","address":"198\.18\.67\.4","family":"inet","fib":0,"state":"up"' \
	    -o match:'"stamp":\{"target":"svc/a-b","kind":"stamp","method":"stamp","reason":"no STAMP reply in 5 probes"' \
	    "$JGC" -c "$SOCK" sdwan
	atf_check -o match:'probe: svc/a-b \(198\.18\.67\.2\): no STAMP reply in 5 probes: STAMP alone, no fallback' \
	    -o not-match:'probe: svc/a-b .*pinged until STAMP answers' cat daemon.out
	atf_check -o empty "$JGC" -c "$SOCK" sdwan probes '[]'
}
stamp_kinds_cleanup()
{
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	[ -f stk.spid ] && kill "$(cat stk.spid)" 2>/dev/null
	jexec $STK_J ipfw -q flush 2>/dev/null
	# The epair's end brought home before the jail goes.
	if [ -f stk.epair ]; then
		ep=$(cat stk.epair)
		ifconfig "${ep%a}b" -vnet $STK_J 2>/dev/null
		ifconfig "$ep" destroy 2>/dev/null
	fi
	jail -r $STK_J >/dev/null 2>&1
	true
}

atf_test_case monitors_qos cleanup
monitors_qos_head()
{
	atf_set "descr" "Tunnel monitors against what dummynet(4) makes: a gif between two vnet jails measured from both sides, overlay and underlay, each in its own FIB; the underlay's delay and loss seen in both, the overlay's own delay in it alone, a probe in the wrong FIB reaching nothing"
	atf_set "require.user" "root"
	atf_set "is.exclusive" "true"
}
monitors_qos_body()
{
	kldstat -q -m dummynet || atf_skip "dummynet(4) is not loaded"
	kldstat -q -m ipfw || atf_skip "ipfw(4) is not loaded"
	# A new vnet's ipfw starts with the default rule: deny would cut it.
	[ "$(sysctl -n net.inet.ip.fw.default_to_accept)" = 1 ] ||
	    atf_skip "net.inet.ip.fw.default_to_accept is not 1"
	command -v python3 >/dev/null || atf_skip "no python3 to read the samples"
	start_daemon
	qos_lab_up
	ga=$(cat qos.gifa)
	gb=$(cat qos.gifb)
	# Each end, as the fleet's Quality view sets them: the overlay to
	# the far inner address in the interface's table, the underlay to
	# the far outer address in its tunnelfib.
	atf_check -o match:done "$JGC" -c "$SOCK" -j $QOS_A monitor set \
	    name=ov-"$ga" interface="$ga" address=10.99.0.2 interval=50 eval=1000
	atf_check -o match:done "$JGC" -c "$SOCK" -j $QOS_A monitor set \
	    name=ul-"$ga" interface="$ga" address=192.0.2.2 fib=1 interval=50 \
	    eval=1000
	atf_check -o match:done "$JGC" -c "$SOCK" -j $QOS_B monitor set \
	    name=ov-"$gb" interface="$gb" address=10.99.0.1 interval=50 eval=1000
	atf_check -o match:done "$JGC" -c "$SOCK" -j $QOS_B monitor set \
	    name=ul-"$gb" interface="$gb" address=192.0.2.1 interval=50 eval=1000
	# A's underlay is in its FIB 1: from FIB 0 nothing is reached.
	atf_check -o match:done "$JGC" -c "$SOCK" -j $QOS_A monitor set \
	    name=wrong-fib address=192.0.2.2 fib=0 interval=50 eval=1000 down=3
	sleep 12
	atf_check -o save:m.json "$JGC" -c "$SOCK" monitor
	cat > qos.py <<'EOF'
import json, sys
m = {(x.get("jail", ""), x["id"]): x for x in json.load(open("m.json"))["monitors"]}
def means(key):
    s = [r for r in m[key]["samples"][1:] if r[6] > 0]
    sent = sum(r[6] for r in s); recv = sum(r[7] for r in s)
    got = [r for r in s if r[7] > 0]
    return (sum(r[1] for r in got) / len(got) if got else -1,
        sum(r[2] for r in got) / len(got) if got else -1,
        1 - recv / sent if sent else -1, sent, m[key]["state"])
bad = []
for side, jail, gif in (("A", sys.argv[1], sys.argv[3]), ("B", sys.argv[2], sys.argv[4])):
    ov = means((jail, "ov-" + gif)); ul = means((jail, "ul-" + gif))
    print(side, "overlay delay %.1f ipdv %.1f loss %.2f (%d) %s" % ov)
    print(side, "underlay delay %.1f ipdv %.1f loss %.2f (%d) %s" % ul)
    # Half of a 10-20 ms round trip (dummynet's ticks), and 30 more.
    if not 4 <= ul[0] <= 15: bad.append(side + " underlay delay")
    if not 15 <= ov[0] <= 35: bad.append(side + " overlay delay")
    if not ov[0] > ul[0] + 7: bad.append(side + " overlay not slower")
    # A fifth lost, each probe crossing the shaped underlay once.
    for n, v in (("overlay", ov), ("underlay", ul)):
        if v[3] < 100: bad.append(side + " " + n + " too few probes")
        if not 0.05 <= v[2] <= 0.45: bad.append(side + " " + n + " loss")
        if not v[1] > 0: bad.append(side + " " + n + " no variation")
        if v[4] != "up": bad.append(side + " " + n + " not up")
w = means((sys.argv[1], "wrong-fib"))
print("A wrong fib loss %.2f %s" % (w[2], w[4]))
if w[2] != 1 or w[4] != "down": bad.append("A's FIB 0 reached the underlay")
print("bad:", ", ".join(bad) if bad else "none")
sys.exit(1 if bad else 0)
EOF
	atf_check -o match:'^bad: none$' python3 qos.py $QOS_A $QOS_B "$ga" "$gb"
	atf_check -o match:'"kind":"monitor","data":\{"id":"wrong-fib","address":"192.0.2.2","state":"down"' \
	    "$JGC" -c "$SOCK" events
}
monitors_qos_cleanup()
{
	qos_lab_down
	cleanup
}

# ietf-interfaces' layers: a vlan on a lagg of two
# ports, a bridge of two members, all made here of epairs and destroyed.
atf_test_case yang_layers cleanup
yang_layers_head()
{
	atf_set "descr" "ietf-interfaces' layers: a vlan on a lagg on two" \
	    "ports, a bridge on two members"
	atf_set "require.user" "root"
}
yang_layers_body()
{
	# A cloner the kernel has: kldload(8) is the host's, not a jail's.
	ifconfig -C | tr ' ' '\n' | grep -qx lagg ||
	    atf_skip "no lagg(4): kldload if_lagg on the host"
	e1=$(epair_create) && echo "$e1" >> made
	e2=$(epair_create) && echo "$e2" >> made
	p1=${e1%a}b
	p2=${e2%a}b
	lg=$(ifconfig lagg create) && echo "$lg" >> made
	atf_check ifconfig "$lg" laggproto failover laggport "$e1" \
	    laggport "$e2" up
	vl=$(ifconfig vlan create vlan 42 vlandev "$lg") && echo "$vl" >> made
	br=$(ifconfig bridge create) && echo "$br" >> made
	atf_check ifconfig "$br" addm "$p1" addm "$p2" up
	atf_check -o save:y "$(atf_get_srcdir)/ycollect" interfaces
	atf_check -o match:" lower=$lg higher=- *\$" grep "^$vl " y
	# A leaf-list the system orders: the members in either order.
	atf_check -o match:" lower=($e1,$e2|$e2,$e1) higher=$vl *\$" \
	    grep "^$lg " y
	atf_check -o match:" lower=- higher=$lg *\$" grep "^$e1 " y
	atf_check -o match:" lower=- higher=$lg *\$" grep "^$e2 " y
	atf_check -o match:" lower=($p1,$p2|$p2,$p1) higher=- *\$" \
	    grep "^$br " y
	atf_check -o match:" lower=- higher=$br *\$" grep "^$p1 " y
	atf_check -o match:" lower=- higher=$br *\$" grep "^$p2 " y
	# A lagg's port is the Ethernet it was; the lagg the aggregate.
	atf_check -o match:" type=ethernetCsmacd " grep "^$e1 " y
	atf_check -o match:" type=ieee8023adLag " grep "^$lg " y
	atf_check -o match:" type=l2vlan " grep "^$vl " y
	atf_check -o match:'^yang-cbor [0-9]+ bytes, the same back$' tail -1 y
}
yang_layers_cleanup()
{
	# What was made, the last first: the vlan and bridge, the lagg,
	# then the epairs (destroying an a end takes its b end too).
	[ -f made ] && tail -r made | while read -r i; do
		ifconfig "$i" destroy >/dev/null 2>&1
	done
	true
}

# arcana-interfaces: each kind of interface the
# agent's jobs make, read back.  What no job sets (a lagg's ports, a
# vlan's priority, STP on a bridge's member) ifconfig does.
atf_test_case yang_kinds cleanup
yang_kinds_head()
{
	atf_set "descr" "arcana-interfaces reads back what the agent's jobs" \
	    "made: a vlan on a lagg, a bridge, a gif's tunnel FIB, an MTU" \
	    "and a FIB, an epair whose other end is in a vnet jail"
	atf_set "require.user" "root"
}
yang_kinds_body()
{
	local y="$(atf_get_srcdir)/ycollect"

	[ "$(sysctl -n net.fibs)" -ge 2 ] || atf_skip "net.fibs is 1"
	# A cloner the kernel has: kldload(8) is the host's, not a jail's.
	ifconfig -C | tr ' ' '\n' | grep -qx lagg ||
	    atf_skip "no lagg(4): kldload if_lagg on the host"
	for i in epair77a epair78a epair79a epair80a vlan77 vlan78 lagg77 lagg78 \
	    bridge77 gif77; do
		ifconfig "$i" >/dev/null 2>&1 && atf_skip "$i exists"
	done
	jls -j "$YJAIL" >/dev/null 2>&1 && atf_skip "a jail named $YJAIL exists"
	start_daemon
	touch made
	for e in epair77 epair78 epair79; do
		atf_check -o ignore "$JGC" -c "$SOCK" interface "$e" create
		echo "${e}a" >> made
	done
	atf_check -o ignore "$JGC" -c "$SOCK" interface epair77a mtu 1400
	atf_check -o ignore "$JGC" -c "$SOCK" interface epair77a fib 1
	atf_check -o ignore "$JGC" -c "$SOCK" interface lagg77 create
	echo lagg77 >> made
	atf_check ifconfig lagg77 laggproto loadbalance lagghash l3,l4 \
	    laggport epair78a
	atf_check -o ignore ifconfig epair80 create
	echo epair80a >> made
	atf_check -o ignore ifconfig lagg78 create
	echo lagg78 >> made
	atf_check ifconfig lagg78 laggproto lacp laggport epair80a
	atf_check -o ignore "$JGC" -c "$SOCK" interface vlan77 create id 77 \
	    parent lagg77
	echo vlan77 >> made
	atf_check ifconfig vlan77 vlanpcp 5
	atf_check -o ignore ifconfig vlan78 create vlan 78 vlandev epair79a \
	    vlanproto 802.1ad
	echo vlan78 >> made
	atf_check -o ignore "$JGC" -c "$SOCK" interface bridge77 create \
	    parent epair77b
	echo bridge77 >> made
	atf_check ifconfig bridge77 stp epair77b
	atf_check -o ignore "$JGC" -c "$SOCK" interface gif77 create tunnel \
	    192.0.2.77 192.0.2.78 tunnelfib 1
	echo gif77 >> made
	atf_check -o ignore jail -c name="$YJAIL" path=/ vnet persist
	atf_check -o ignore "$JGC" -c "$SOCK" interface epair79b give "$YJAIL"

	atf_check -o save:a "$y" arcif
	atf_check -o save:i "$y" interfaces
	atf_check -o match:'^yang-cbor [0-9]+ bytes, the same back$' tail -1 a
	# The MTU as ietf-if-extensions' max-frame-size: 1400, an Ethernet
	# header and FCS, and a tag (epair has VLAN_MTU); the other end as
	# its peer-interface; the FIB as RFC 8529's bind-ni-name.
	atf_check -o match:' frame=1422 .* peer=epair77b( |$)' \
	    grep '^epair77a ' a
	atf_check -o match:' peer=epair77a( |$)' grep '^epair77b ' a
	atf_check -o match:' peer=vnet( |$)' grep '^epair79a ' a
	atf_check -o match:'^epair77a 1 fib1 ' "$(atf_get_srcdir)/yni" -i -
	atf_check -o match:' tunnelfib=1 ' grep '^gif77 ' a
	atf_check -o match:' type=tunnel ' grep '^gif77 ' i
	# IEEE 802.1AX's: each lagg a key group and system of its name, its
	# lag and its port's aggport naming it; FreeBSD's loadbalance,
	# hashing l3 and l4 (bits 1 and 2); with LACP the port's number and
	# state, the system's priority.
	atf_check -o match:' lagg=loadbalance,6,[0-9A-F-]{17}( |$)' \
	    grep '^lagg77 ' a
	atf_check -o match:' aggport=lagg77,[0-9]+:[0-9a-f]+( |$)' \
	    grep '^epair78a ' a
	atf_check -o match:' lagg=lacp,[0-9a-f]+,[0-9A-F-]{17},key=[0-9]+' \
	    grep '^lagg78 ' a
	# The port's actor state: ifconfig's, LACP_STATE_* bits one
	# position on in IEEE's lacp-state (lacp-activity is position 1).
	st=$(ifconfig -v lagg78 | sed -n 's/.*laggport: epair80a .*state=\([0-9a-f]*\)<.*/\1/p')
	[ -n "$st" ] || atf_fail "ifconfig shows no LACP state for epair80a"
	st=$(printf '%x' $((0x$st << 1)))
	atf_check -o match:" aggport=lagg78,[0-9]+:[0-9a-f]+,port=[0-9]+,state=$st( |\$)" \
	    grep '^epair80a ' a
	atf_check -o save:la "$y" linkagg
	atf_check -o match:'^yang-cbor [0-9]+ bytes, the same back$' tail -1 la
	atf_check -o match:'^lagg77 system=lagg77,[0-9A-F-]{17},- lags=lagg77 aggports=epair78a$' \
	    grep '^lagg77 ' la
	atf_check -o match:'^lagg78 system=lagg78,[0-9A-F-]{17},[0-9]+ lags=lagg78 aggports=epair80a$' \
	    grep '^lagg78 ' la
	# ietf-if-vlan-encapsulation's outer tag, an 802.1Q one c-vlan; the
	# parent ietf-if-extensions'; the priority arcana-interfaces'.
	atf_check -o match:' vlan=77,lagg77,c-vlan,5' grep '^vlan77 ' a
	atf_check -o match:' vlan=78,epair79a,s-vlan,0' grep '^vlan78 ' a
	# IEEE 802.1Q's: the bridge, its one VLAN-unaware component and its
	# port; the member's bridge-port and, its STP on, RSTP's port, each
	# as ifconfig shows the member: flags (FreeBSD's own the learn,
	# discover, span, sticky, private and qinq ones), port, priority
	# (IEEE's a sixteenth of it), path cost, role and state (RSTP's:
	# disabled, listening and blocking discarding).
	atf_check -o save:br "$y" bridges
	atf_check -o match:'^yang-cbor [0-9]+ bytes, the same back$' tail -1 br
	atf_check -o match:'^bridge77 address=[0-9A-F-]{17} type=customer-vlan-bridge component=bridge77,d-bridge-component ports=epair77b$' \
	    grep '^bridge77 ' br
	ifconfig bridge77 | awk '
	$1 == "member:" { m = $2 == "epair77b"; if (m) { f = $3; sub(/^flags=/, "", f); sub(/<.*/, "", f) } next }
	!m { next }
	{ for (i = 1; i < NF; i++) {
		if ($i == "port") port = $(i + 1)
		if ($i == "priority") prio = $(i + 1)
		if ($i == "cost") cost = $(i + 1)
		if ($i == "role") role = $(i + 1)
		if ($i == "state") state = $(i + 1)
	} }
	END { print f, port, prio, cost, role, state }' > member
	read -r f port prio cost role state < member
	[ -n "$f" ] || atf_fail "ifconfig shows no member epair77b"
	f=$((0x$f))
	[ $((f & 0x100)) -ne 0 ] && p2p=auto ||
	    { [ $((f & 0x80)) -ne 0 ] && p2p=force-true || p2p=force-false; }
	[ $((f & 0x80)) -ne 0 ] && ptp=on || ptp=off
	own=$(printf '%x' $((f & 0x181b)))
	atf_check -o match:" bport=bridge77,$port,$p2p/$ptp,$own( |\$)" \
	    grep '^epair77b ' a
	[ $((f & 0x4)) -ne 0 ] || atf_fail "ifconfig stp did not turn STP on"
	case "$state" in learning|forwarding) ;; *) state=discarding ;; esac
	[ $((f & 0x400)) -ne 0 ] && fixed=fixed || fixed=auto
	atf_check -o match:" rstp=$state,$role,$((prio >> 4))/$port/$(((prio >> 4) << 12 | port)),$cost/$fixed,edge=$(((f >> 9) & 1))/$(((f >> 5) & 1))/$(((f >> 6) & 1))( |\$)" \
	    grep '^epair77b ' a
}
yang_kinds_cleanup()
{
	cleanup
	# Out of the vnet jail first: it is not removed with one inside.
	ifconfig epair79b -vnet "$YJAIL" >/dev/null 2>&1
	[ -f made ] && tail -r made | while read -r i; do
		ifconfig "$i" destroy >/dev/null 2>&1
	done
	jail -r "$YJAIL" >/dev/null 2>&1
	true
}

# The events ietf-interfaces' list changes by,
# netlink(4)'s RTNLGRP_LINK as the agent watches it: an interface made,
# changed, renamed (gone by its old name, come by its new one) and
# destroyed, the collector's list agreeing after each.
atf_test_case yang_events cleanup
yang_events_head()
{
	atf_set "descr" "an interface made, changed, renamed and destroyed:" \
	    "each a link event, and the collector's list as it says"
	atf_set "require.user" "root"
}
yang_events_body()
{
	local y="$(atf_get_srcdir)/ycollect"

	for i in epair76a epair76b yev76; do
		ifconfig "$i" >/dev/null 2>&1 && atf_skip "$i exists"
	done
	start_daemon
	last=$("$JGC" -c "$SOCK" events | sed -E 's/^\{"last":([0-9]+).*/\1/')
	atf_check -o ignore ifconfig epair76 create
	echo epair76a > made
	atf_check ifconfig epair76a mtu 1400 up
	echo yev76 >> made
	atf_check -o inline:'yev76\n' ifconfig epair76a name yev76
	atf_check -o save:y "$y" interfaces
	atf_check -o match:'^yev76 index=[0-9]+ admin=up ' grep '^yev76 ' y
	atf_check -s exit:1 grep '^epair76a ' y
	atf_check ifconfig yev76 destroy
	atf_check -o save:y2 "$y" interfaces
	atf_check -s exit:1 grep -E '^(yev76|epair76b) ' y2
	sleep 0.5
	atf_check -o save:ev "$JGC" -c "$SOCK" events "$last"
	atf_check -o match:'"kind":"link","data":\{"interface":"epair76a","up":false' \
	    -o match:'"kind":"link","data":\{"interface":"epair76a","up":true,"carrier":true,"mtu":1400' \
	    -o match:'"kind":"link-del","data":\{"interface":"epair76a"' \
	    -o match:'"kind":"link","data":\{"interface":"yev76"' \
	    -o match:'"kind":"link-del","data":\{"interface":"yev76"' \
	    -o match:'"kind":"link-del","data":\{"interface":"epair76b"' cat ev
}
yang_events_cleanup()
{
	cleanup
	# By either name: renamed or not when the case stopped.
	[ -f made ] && while read -r i; do
		ifconfig "$i" destroy >/dev/null 2>&1
	done < made
	true
}

# ietf-ip's origins and statuses on a lab epair:
# deprecated, autoconfigured from the link address or not, link-local,
# IPv4 link-local, a duplicate DAD finds against the other end in a vnet
# jail, and IPv6 turned off.  (dhcp needs a server base has not.)
atf_test_case yang_ip cleanup
yang_ip_head()
{
	atf_set "descr" "ietf-ip's origins and statuses: deprecated," \
	    "autoconf by EUI-64 or not, link-local, 169.254/16, duplicate," \
	    "IPv6 off"
	atf_set "require.user" "root"
}
yang_ip_body()
{
	local y="$(atf_get_srcdir)/ycollect" e=epair75a b=epair75b

	ifconfig "$e" >/dev/null 2>&1 && atf_skip "$e exists"
	jls -j "$YJAIL" >/dev/null 2>&1 && atf_skip "a jail named $YJAIL exists"
	atf_check -o ignore ifconfig epair75 create
	echo "$e" > made
	atf_check -o ignore jail -c name="$YJAIL" path=/ vnet persist
	atf_check ifconfig "$b" vnet "$YJAIL"
	atf_check ifconfig "$e" up
	atf_check jexec "$YJAIL" ifconfig "$b" inet6 2001:db8:78::1/64 up
	atf_check ifconfig "$e" inet6 2001:db8:75::1/64 deprecated
	atf_check ifconfig "$e" inet6 2001:db8:76::/64 eui64 autoconf
	atf_check ifconfig "$e" inet6 2001:db8:77::5/64 autoconf
	atf_check ifconfig "$e" inet 169.254.7.5/16
	sleep 1
	atf_check ifconfig "$e" inet6 2001:db8:78::1/64
	# DAD: a probe a second (net.inet6.ip6.dad_count), then its verdict.
	for i in 1 2 3 4 5 6; do
		ifconfig "$e" | grep -q '2001:db8:78::1 .*duplicated' && break
		sleep 1
	done
	atf_check -o save:ip "$y" ip
	atf_check -o save:addrs sh -c "grep '^$e ' ip | tr '+ ' '\n\n'"
	atf_check -o match:'^v4=169\.254\.7\.5/16:random$' \
	    -o match:'^v6=2001:db8:75::1/64:static:deprecated$' \
	    -o match:'^fe80::[0-9a-f:]+/64:link-layer:preferred$' \
	    -o match:'^2001:db8:76:0:[0-9a-f:]+/64:link-layer:preferred$' \
	    -o match:'^2001:db8:77::5/64:random:preferred$' \
	    -o match:'^2001:db8:78::1/64:static:duplicate$' \
	    -o match:'^ipv6=on,1500$' cat addrs
	# Neighbours (1.10.2): set by hand, static, no state; one learnt,
	# dynamic, its link address the other end's; the host's own, none.
	atf_check arp -s 169.254.7.9 02:00:00:00:75:09
	atf_check -o ignore ndp -s 2001:db8:75::9 02:00:00:00:75:0a
	atf_check jexec "$YJAIL" ifconfig "$b" inet6 2001:db8:79::2/64
	atf_check ifconfig "$e" inet6 2001:db8:79::1/64
	sleep 2
	atf_check -o ignore ping6 -c 1 -t 5 2001:db8:79::2
	bll=$(jexec "$YJAIL" ifconfig "$b" ether | awk '$1 == "ether" { print $2 }')
	atf_check -o save:nb "$y" nb
	atf_check -o match:"^$e inet 169\.254\.7\.9 02:00:00:00:75:09 static\$" \
	    -o match:"^$e inet6 2001:db8:75::9 02:00:00:00:75:0a static - -\$" \
	    -o match:"^$e inet6 2001:db8:79::2 $bll dynamic - (reachable|stale|delay|probe)\$" \
	    -o not-match:"^$e inet 169\.254\.7\.5 " \
	    -o not-match:"^$e inet6 2001:db8:79::1 " cat nb
	# RAs' addresses are the interface's own to make.
	atf_check ifconfig "$e" inet6 accept_rtadv
	atf_check -o match:" global=1\$" sh -c "\"$y\" ipsys | grep '^$e '"
	atf_check ifconfig "$e" inet6 ifdisabled
	atf_check -o match:" ipv6=off,1500\$" sh -c "\"$y\" ip | grep '^$e '"
}
atf_test_case yang_ecmp cleanup
yang_ecmp_head()
{
	atf_set "descr" "ietf-routing's next-hop-list:" \
	    "a prefix with two gateways, IPv4 and IPv6, in a vnet" \
	    "jail's FIB"
	atf_set "require.user" "root"
}
yang_ecmp_body()
{
	local y="$(atf_get_srcdir)/ycollect" e=epair74a b=epair74b

	[ "$(sysctl -n net.route.multipath 2>/dev/null)" = 1 ] ||
	    atf_skip "no multipath routes (net.route.multipath)"
	ifconfig "$e" >/dev/null 2>&1 && atf_skip "$e exists"
	jls -j "$YJAIL" >/dev/null 2>&1 && atf_skip "a jail named $YJAIL exists"
	atf_check -o ignore ifconfig epair74 create
	echo "$e" > made
	atf_check -o ignore jail -c name="$YJAIL" path=/ vnet persist
	atf_check ifconfig "$b" vnet "$YJAIL"
	atf_check jexec "$YJAIL" ifconfig "$b" inet 192.0.2.10/24 up
	atf_check jexec "$YJAIL" ifconfig "$b" inet6 2001:db8:74::10/64 \
	    no_dad
	for g in 1 2; do
		atf_check -o ignore jexec "$YJAIL" route add -net \
		    198.51.100.0/24 192.0.2.$g
		atf_check -o ignore jexec "$YJAIL" route add -inet6 -net \
		    2001:db8:75::/48 2001:db8:74::$g
	done
	atf_check -o save:r jexec "$YJAIL" "$y" routes 0
	atf_check -o match:'^yang-cbor [0-9]+ bytes, the same back$' \
	    tail -1 r
	# One route, two next hops of its next-hop-list, the interface and
	# the gateway each; a static route's.
	atf_check -o inline:"inet 198.51.100.0/24 192.0.2.1 $b - static multipath
inet 198.51.100.0/24 192.0.2.2 $b - static multipath
inet6 2001:db8:75::/48 2001:db8:74::1 $b - static multipath
inet6 2001:db8:75::/48 2001:db8:74::2 $b - static multipath
" sh -c "grep ' multipath\$' r | sort"
	# One gateway left: a simple next hop again.
	atf_check -o ignore jexec "$YJAIL" route delete -net 198.51.100.0/24 \
	    192.0.2.2
	atf_check -o save:r2 jexec "$YJAIL" "$y" routes 0
	atf_check -o inline:"inet 198.51.100.0/24 192.0.2.1 $b - static -
" sh -c "grep '^inet 198\.51\.100\.0/24 ' r2"
}
atf_test_case yang_static_apply cleanup
yang_static_apply_head()
{
	atf_set "descr" "rc.conf's static routes made a vnet jail's FIBs'" \
	    "by netlink, undone, and undone on a" \
	    "failure"
	atf_set "require.user" "root"
}
yang_static_apply_body()
{
	local y="$(atf_get_srcdir)/yrcroutes" c="$(atf_get_srcdir)/ycollect"
	local e=epair73a b=epair73b

	ifconfig "$e" >/dev/null 2>&1 && atf_skip "$e exists"
	jls -j "$YJAIL" >/dev/null 2>&1 && atf_skip "a jail named $YJAIL exists"
	atf_check -o ignore ifconfig epair73 create
	echo "$e" > made
	atf_check -o ignore jail -c name="$YJAIL" path=/ vnet persist
	atf_check ifconfig "$b" vnet "$YJAIL"
	# A host's loopback, which a blackhole or reject route goes by.
	atf_check jexec "$YJAIL" ifconfig lo0 inet 127.0.0.1/8 up
	atf_check jexec "$YJAIL" ifconfig lo0 inet6 ::1/128
	atf_check jexec "$YJAIL" ifconfig "$b" inet 192.0.2.5/24 up
	atf_check jexec "$YJAIL" ifconfig "$b" inet6 2001:db8:73::5/64 no_dad
	: > "$PWD/none.conf"
	cat > routes.conf <<EOF
defaultrouter="192.0.2.254"
static_routes="a e1 e2 bh rj ifr"
route_a="-net 10.2.0.0/16 192.0.2.10"
route_e1="-net 10.8.0.0/24 192.0.2.21"
route_e2="-net 10.8.0.0/24 192.0.2.22"
route_bh="-net 203.0.113.0/24 127.0.0.1 -blackhole"
route_rj="-host 203.0.113.9 127.0.0.1 -reject"
route_ifr="-net 10.9.0.0/24 -iface $b"
ipv6_static_routes="v6a"
ipv6_route_v6a="2001:db8:1::/48 2001:db8:73::1"
ipv6_defaultrouter="fe80::1%$b"
EOF
	atf_check jexec "$YJAIL" "$y" -a 0 "$PWD/none.conf" "$PWD/routes.conf"
	atf_check -o save:r jexec "$YJAIL" "$c" routes 0
	atf_check -o inline:"inet 0.0.0.0/0 192.0.2.254 $b - static -
inet 10.2.0.0/16 192.0.2.10 $b - static -
inet 10.8.0.0/24 192.0.2.21 $b - static multipath
inet 10.8.0.0/24 192.0.2.22 $b - static multipath
inet 10.9.0.0/24 - $b - static -
inet 203.0.113.0/24 - - blackhole static -
inet 203.0.113.9/32 - - unreachable static -
inet6 2001:db8:1::/48 2001:db8:73::1 $b - static -
inet6 ::/0 fe80::1%$b $b - static -
" sh -c "grep ' static ' r | grep -v ' receive ' | LC_ALL=C sort"
	# route(8)'s own word on two of them.
	atf_check -o match:'gateway: 192\.0\.2\.10' \
	    -o match:'flags: <UP,GATEWAY,DONE,STATIC>' \
	    jexec "$YJAIL" route -n get 10.2.3.4
	atf_check -o match:'flags: <UP,DONE,STATIC,BLACKHOLE>' \
	    jexec "$YJAIL" route -n get 203.0.113.1
	# A route changed: only it.
	sed 's/192\.0\.2\.10"/192.0.2.11"/' routes.conf > "$PWD/routes2.conf"
	atf_check jexec "$YJAIL" "$y" -a 0 "$PWD/routes.conf" "$PWD/routes2.conf"
	atf_check -o match:'gateway: 192\.0\.2\.11' \
	    jexec "$YJAIL" route -n get 10.2.3.4
	# All taken away: none left.
	atf_check jexec "$YJAIL" "$y" -a 0 "$PWD/routes2.conf" "$PWD/none.conf"
	atf_check -o empty sh -c "jexec '$YJAIL' '$c' routes 0 | \
	    grep ' static ' | grep -v ' receive ' || true"
	# One that fails, its interface not there: none of them stays.
	printf 'static_routes="a z"\nroute_a="-net 10.2.0.0/16 192.0.2.10"\nroute_z="-net 10.3.0.0/16 -iface nosuch0"\n' > "$PWD/bad.conf"
	atf_check -s exit:1 -e match:'no interface nosuch0' \
	    jexec "$YJAIL" "$y" -a 0 "$PWD/none.conf" "$PWD/bad.conf"
	atf_check -s not-exit:0 -o ignore -e ignore \
	    jexec "$YJAIL" route -n get 10.2.3.4
	# Another FIB's, with -fib: there, not in FIB 0.  net.fibs is the
	# jail's own (its vnet's), raised for it there.
	if jexec "$YJAIL" sysctl net.fibs=2 >/dev/null 2>&1; then
		# By the interface: 192.0.2.0/24 is FIB 0's alone
		# (net.add_addr_allfibs), no gateway in it reached from 1.
		printf 'static_routes="f"\nroute_f="-net 10.5.0.0/24 -iface %s -fib 1"\n' "$b" > fib.conf
		atf_check jexec "$YJAIL" "$y" -a 1 "$PWD/none.conf" "$PWD/fib.conf"
		atf_check -o match:"interface: $b" \
		    jexec "$YJAIL" route -n get -fib 1 10.5.0.1
		atf_check -s not-exit:0 -o ignore -e ignore \
		    jexec "$YJAIL" route -n get 10.5.0.1
		atf_check jexec "$YJAIL" "$y" -a 1 "$PWD/fib.conf" "$PWD/none.conf"
	fi
}
atf_test_case yang_route_times cleanup
yang_route_times_head()
{
	atf_set "descr" "ietf-routing's last-updated:" \
	    "a route added while route events are heard has the time, one" \
	    "not seen to change none"
	atf_set "require.user" "root"
}
yang_route_times_body()
{
	local c="$(atf_get_srcdir)/ycollect" e=epair72a b=epair72b

	ifconfig "$e" >/dev/null 2>&1 && atf_skip "$e exists"
	jls -j "$YJAIL" >/dev/null 2>&1 && atf_skip "a jail named $YJAIL exists"
	atf_check -o ignore ifconfig epair72 create
	echo "$e" > made
	atf_check -o ignore jail -c name="$YJAIL" path=/ vnet persist
	atf_check ifconfig "$b" vnet "$YJAIL"
	atf_check jexec "$YJAIL" ifconfig "$b" inet 192.0.2.5/24 up
	jexec "$YJAIL" "$c" watch 0 4 > out &
	for i in 1 2 3 4 5 6 7 8 9 10; do
		grep -q '^watching$' out 2>/dev/null && break
		sleep 0.2
	done
	before=$(date -u +%Y-%m-%dT%H:%M:%SZ)
	atf_check -o ignore jexec "$YJAIL" route add -net 198.51.100.0/24 \
	    192.0.2.1
	after=$(date -u +%Y-%m-%dT%H:%M:%SZ)
	wait
	t=$(awk '$2 == "198.51.100.0/24" { print $8 }' out)
	[ -n "$t" ] && [ "$t" != - ] || { cat out; atf_fail \
	    "198.51.100.0/24: no last-updated"; }
	# The same format sorts as the times do: within the add.
	[ ! "$t" \< "$before" ] && [ ! "$t" \> "$after" ] ||
	    atf_fail "last-updated $t, not between $before and $after"
	atf_check -o inline:"-\n" awk '$2 == "192.0.2.0/24" { print $8 }' out
}
yang_route_times_cleanup()
{
	ifconfig epair72b -vnet "$YJAIL" >/dev/null 2>&1
	[ -f made ] && ifconfig "$(cat made)" destroy >/dev/null 2>&1
	jail -r "$YJAIL" >/dev/null 2>&1
	true
}

atf_test_case yang_lne cleanup
yang_lne_head()
{
	atf_set "descr" "logical network elements: a" \
	    "vnet jail is one, a jail sharing the host's stack is not; as" \
	    "jls says"
	atf_set "require.user" "root"
}
yang_lne_body()
{
	local c="$(atf_get_srcdir)/ycollect"

	jls -j "$YJAIL" >/dev/null 2>&1 && atf_skip "a jail named $YJAIL exists"
	jls -j "${YJAIL}2" >/dev/null 2>&1 &&
	    atf_skip "a jail named ${YJAIL}2 exists"
	atf_check -o ignore jail -c name="$YJAIL" path=/ vnet persist
	atf_check -o ignore jail -c name="${YJAIL}2" path=/ persist
	atf_check -o match:"^$YJAIL managed\$" -o not-match:"^${YJAIL}2 " \
	    "$c" lne
	# jls's vnet parameter: new for a stack of its own.
	jls -n name vnet | sed -n 's/^name=\(.*\) vnet=new$/\1 managed/p' | \
	    sort > want
	"$c" lne | grep -v '^yang-cbor' | sort > got
	atf_check -o inline:"$YJAIL managed\n" grep "^$YJAIL " want
	atf_check cmp want got
}
yang_lne_cleanup()
{
	jail -r "${YJAIL}2" >/dev/null 2>&1
	jail -r "$YJAIL" >/dev/null 2>&1
	true
}

atf_test_case yang_ni cleanup
yang_ni_head()
{
	atf_set "descr" "network instances on a host with net.fibs=4" \
	    ": a vnet jail's, raised to 4"
	atf_set "require.user" "root"
}
yang_ni_body()
{
	local y="$(atf_get_srcdir)/yni"

	jls -j "$YJAIL" >/dev/null 2>&1 && atf_skip "a jail named $YJAIL exists"
	atf_check -o ignore jail -c name="$YJAIL" path=/ vnet persist
	atf_check -o ignore jexec "$YJAIL" sysctl net.fibs=4
	printf 'fib2_name="blue"\nfib2_description="the blue one"\n' > \
	    fibs.conf
	atf_check -o inline:"fib1 1 -
blue 2 the blue one
fib3 3 -
yang-cbor 59 bytes, the same back
" jexec "$YJAIL" "$y" "$PWD/fibs.conf"
}
atf_test_case yang_ni_grow cleanup
yang_ni_grow_head()
{
	atf_set "descr" "an instance past the last FIB:" \
	    "net.fibs raised live and kept in loader.conf; a vnet jail's"
	atf_set "require.user" "root"
}
yang_ni_grow_body()
{
	local y="$(atf_get_srcdir)/yni" n

	jls -j "$YJAIL" >/dev/null 2>&1 && atf_skip "a jail named $YJAIL exists"
	atf_check -o ignore jail -c name="$YJAIL" path=/ vnet persist
	# A new vnet has the boot's; the instance asked for is past it.
	n=$(jexec "$YJAIL" sysctl -n net.fibs)
	: > loader.conf
	: > fibs.conf
	echo "$((n + 2)) far" > in
	atf_check -o inline:"net.fibs $((n + 3)) live\n" \
	    jexec "$YJAIL" sh -c "'$y' -w -l '$PWD/loader.conf' '$PWD/fibs.conf' < '$PWD/in'"
	atf_check -o inline:"$((n + 3))\n" jexec "$YJAIL" sysctl -n net.fibs
	atf_check -o inline:"net.fibs=\"$((n + 3))\"\n" cat loader.conf
	atf_check -o match:"^far $((n + 2)) -$" \
	    jexec "$YJAIL" "$y" "$PWD/fibs.conf"
}
yang_ni_grow_cleanup()
{
	jail -r "$YJAIL" >/dev/null 2>&1
	true
}

yang_ni_cleanup()
{
	jail -r "$YJAIL" >/dev/null 2>&1
	true
}

atf_test_case yang_ni_bind cleanup
yang_ni_bind_head()
{
	atf_set "descr" "bind-ni-name: ifconfig's fib" \
	    "read back as the instance's name, a name applied by SIOCSIFFIB" \
	    "and kept in rc.conf, bind-ni-name-failed; a vnet jail's epair"
	atf_set "require.user" "root"
}
yang_ni_bind_body()
{
	local y="$(atf_get_srcdir)/yni" e=epair70a b=epair70b

	ifconfig "$e" >/dev/null 2>&1 && atf_skip "$e exists"
	jls -j "$YJAIL" >/dev/null 2>&1 && atf_skip "a jail named $YJAIL exists"
	atf_check -o ignore ifconfig epair70 create
	echo "$e" > made
	atf_check -o ignore jail -c name="$YJAIL" path=/ vnet persist
	atf_check ifconfig "$b" vnet "$YJAIL"
	atf_check -o ignore jexec "$YJAIL" sysctl net.fibs=4
	atf_check jexec "$YJAIL" ifconfig "$b" inet 192.0.2.5/24 up
	printf 'fib2_name="blue"\n' > fibs.conf
	printf 'ifconfig_%s="inet 192.0.2.5/24"\n' "$b" > rc.conf
	# ifconfig fib 2, read back: FIB 2's name, its families' too.
	atf_check jexec "$YJAIL" ifconfig "$b" fib 2
	atf_check -o inline:"$b 2 blue blue blue
back $b blue
yang-cbor the same back
" jexec "$YJAIL" "$y" -i "$PWD/fibs.conf"
	# A name applied: the kernel's, rc.conf's.
	atf_check jexec "$YJAIL" "$y" -b "$b" fib3 "$PWD/fibs.conf" \
	    "$PWD/rc.conf"
	atf_check -o match:'fib: 3$' jexec "$YJAIL" ifconfig "$b"
	atf_check -o inline:"ifconfig_$b=\"inet 192.0.2.5/24 fib 3\"\n" \
	    cat rc.conf
	# Refused, nothing changed: no such instance, a family apart.
	atf_check -s exit:1 \
	    -o inline:"failed $b: nosuch: no such network instance\n" \
	    jexec "$YJAIL" "$y" -b "$b" nosuch "$PWD/fibs.conf" "$PWD/rc.conf"
	atf_check -s exit:1 -o inline:"failed $b: blue: FreeBSD binds an interface, both its address families, not one alone\n" \
	    jexec "$YJAIL" "$y" -b "$b" -4 fib1 blue "$PWD/fibs.conf"
	atf_check -o match:'fib: 3$' jexec "$YJAIL" ifconfig "$b"
	atf_check -o match:'fib 3' cat rc.conf
	# None: FIB 0, the word out.
	atf_check jexec "$YJAIL" "$y" -b "$b" - "$PWD/fibs.conf" \
	    "$PWD/rc.conf"
	atf_check -o not-match:'fib:' jexec "$YJAIL" ifconfig "$b"
	atf_check -o inline:"ifconfig_$b=\"inet 192.0.2.5/24\"\n" cat rc.conf
}
yang_ni_bind_cleanup()
{
	ifconfig epair70b -vnet "$YJAIL" >/dev/null 2>&1
	[ -f made ] && ifconfig "$(cat made)" destroy >/dev/null 2>&1
	jail -r "$YJAIL" >/dev/null 2>&1
	true
}

atf_test_case yang_rtadv cleanup
yang_rtadv_head()
{
	atf_set "descr" "rtadvd.conf edited as the router advertisement" \
	    "submodule, rtadvctl reload, rtadvctl show," \
	    "a lab rtadvd in a vnet jail"
	atf_set "require.user" "root"
}
yang_rtadv_body()
{
	local y="$(atf_get_srcdir)/yrtadv" e=epair71a b=epair71b

	# rtadvctl(8) has its socket at one place: none of the host's.
	pgrep -x rtadvd >/dev/null && atf_skip "rtadvd runs here"
	ifconfig "$e" >/dev/null 2>&1 && atf_skip "$e exists"
	jls -j "$YJAIL" >/dev/null 2>&1 && atf_skip "a jail named $YJAIL exists"
	atf_check -o ignore ifconfig epair71 create
	echo "$e" > made
	atf_check -o ignore jail -c name="$YJAIL" path=/ vnet persist
	atf_check ifconfig "$b" vnet "$YJAIL"
	atf_check jexec "$YJAIL" ifconfig "$b" inet6 2001:db8:71::1/64 up \
	    no_dad
	atf_check -o ignore jexec "$YJAIL" sysctl net.inet6.ip6.forwarding=1
	cat > rtadvd.conf <<EOF
$b:\\
	:maxinterval#600:mininterval#200:rltime#1800:\\
	:addr="2001:db8:71::":prefixlen#64:rdnss="2001:db8:71::53":
EOF
	atf_check jexec "$YJAIL" rtadvd -c "$PWD/rtadvd.conf" \
	    -p "$PWD/rtadvd.pid" -s "$b"
	for i in 1 2 3 4 5 6 7 8 9 10; do
		jexec "$YJAIL" rtadvctl show "$b" 2>/dev/null | \
		    grep -q 'MaxAdvInterval' && break
		sleep 0.5
	done
	atf_check -o match:'MinAdvInterval/MaxAdvInterval: 3m20s/10m' \
	    jexec "$YJAIL" rtadvctl show "$b"
	# Edited as the submodule's max-rtr-adv-interval, reloaded: rtadvd
	# advertises by it.
	atf_check "$y" -m rtadvd.conf "$b" 300
	atf_check -o match:'maxinterval#300' cat rtadvd.conf
	atf_check jexec "$YJAIL" rtadvctl reload "$b"
	for i in 1 2 3 4 5 6 7 8 9 10; do
		jexec "$YJAIL" rtadvctl show "$b" | grep -q '/5m$' && break
		sleep 0.5
	done
	atf_check -o match:'MinAdvInterval/MaxAdvInterval: 3m20s/5m' \
	    jexec "$YJAIL" rtadvctl show "$b"
	# What rtadvd sends, rtadvctl -v show parsed as arcana-ra's rtadvd:
	# the interval edited, the prefix from the file, the DNS server with
	# rtadvd's default lifetime (3/2 of maxinterval).
	jexec "$YJAIL" rtadvctl -v show "$b" > show.txt
	atf_check -o match:'^flags=UP,.*PERSIST$' \
	    -o match:'^max-rtr-adv-interval=300$' \
	    -o match:'^min-rtr-adv-interval=200$' \
	    -o match:'^default-lifetime=1800$' \
	    -o match:'^router-preference=medium$' \
	    -o match:'^interface-prefixes=1$' \
	    -o match:'^prefix 2001:db8:71::/64 config 2592000 604800 1 1$' \
	    -o match:'^rdnss 2001:db8:71::53 450$' \
	    "$y" -s show.txt "$b"
	atf_check -o inline:"none\n" "$y" -s show.txt nothere
}
yang_rtadv_cleanup()
{
	[ -f rtadvd.pid ] && kill "$(cat rtadvd.pid)" >/dev/null 2>&1
	sleep 0.5
	ifconfig epair71b -vnet "$YJAIL" >/dev/null 2>&1
	[ -f made ] && ifconfig "$(cat made)" destroy >/dev/null 2>&1
	jail -r "$YJAIL" >/dev/null 2>&1
	true
}

yang_static_apply_cleanup()
{
	ifconfig epair73b -vnet "$YJAIL" >/dev/null 2>&1
	[ -f made ] && ifconfig "$(cat made)" destroy >/dev/null 2>&1
	jail -r "$YJAIL" >/dev/null 2>&1
	true
}

yang_ecmp_cleanup()
{
	# Out of the vnet jail first: it is not removed with one inside.
	ifconfig epair74b -vnet "$YJAIL" >/dev/null 2>&1
	[ -f made ] && ifconfig "$(cat made)" destroy >/dev/null 2>&1
	jail -r "$YJAIL" >/dev/null 2>&1
	true
}

yang_ip_cleanup()
{
	# Out of the vnet jail first: it is not removed with one inside.
	ifconfig epair75b -vnet "$YJAIL" >/dev/null 2>&1
	[ -f made ] && ifconfig "$(cat made)" destroy >/dev/null 2>&1
	jail -r "$YJAIL" >/dev/null 2>&1
	true
}

atf_test_case yang_jail_actions cleanup
yang_jail_actions_head()
{
	atf_set "descr" "arcana-jails' start, restart and stop actions on a " \
	    "real jail, over cblink's YANG family; the jail read as the " \
	    "module has it in between"
	atf_set "require.user" "root"
}
yang_jail_actions_body()
{
	start_daemon
	atf_check -o match:'^\{"jid":[0-9]+,"state":"running"\}$' \
	    "$JGC" -c "$SOCK" action jails/jail "$JAIL" start
	atf_check -o ignore jls -j "$JAIL"
	atf_check -o match:"\"name\":\"$JAIL\"" -o match:'"state":"running"' \
	    "$JGC" -c "$SOCK" get jails
	atf_check -o match:'"state":"running"' \
	    "$JGC" -c "$SOCK" action jails/jail "$JAIL" restart
	atf_check -o match:'"state":"stopped"' \
	    "$JGC" -c "$SOCK" action jails/jail "$JAIL" stop
	atf_check -s exit:1 -o ignore -e ignore jls -j "$JAIL"
	# Already stopped: the action operation's own refusal.
	atf_check -s exit:1 -o ignore -e match:'not running' \
	    "$JGC" -c "$SOCK" action jails/jail "$JAIL" stop
}
yang_jail_actions_cleanup()
{
	cleanup
}

atf_test_case yang_tunnel cleanup
yang_tunnel_head()
{
	atf_set "descr" "The standard models of a tunnel: its outer " \
	    "addresses and FIB, its point-to-point address's peer, the " \
	    "FIB as a network instance named in fibs.conf"
	atf_set "require.user" "root"
}
yang_tunnel_body()
{
	[ "$(sysctl -n net.fibs)" -ge 3 ] || atf_skip "net.fibs is under 3"
	start_daemon
	g=$(ifconfig gif create) || atf_skip "no gif(4)"
	echo "$g" > gif.name
	# Its FIB first: its addresses' routes go to the FIB it is in.
	atf_check ifconfig "$g" fib 2
	atf_check ifconfig "$g" tunnel 192.0.2.1 192.0.2.2
	atf_check ifconfig "$g" inet 10.77.0.1 10.77.0.2
	atf_check ifconfig "$g" inet6 2001:db8:77::1 2001:db8:77::2 prefixlen 128
	echo 'fib2_name="blue"' > fibs.conf
	echo 'fib2_description="the blue tables"' >> fibs.conf
	atf_check -o save:get.json "$JGC" -c "$SOCK" get interfaces \
	    network-instances
	# Its entry alone: an interface's begins with its admin-status.
	sed 's/{"admin-status"/\n&/g' get.json | grep "\"name\":\"$g\"" \
	    > one.json
	atf_check -o match:'"arcana-interfaces:tunnel":\{"local":"192.0.2.1","remote":"192.0.2.2"\}' \
	    -o match:'"ietf-network-instance:bind-ni-name":"blue"' \
	    -o match:'"ip":"10.77.0.1",[^}]*"arcana-interfaces:peer":"10.77.0.2"' \
	    -o match:'"ip":"2001:db8:77::1",[^}]*"arcana-interfaces:peer":"2001:db8:77::2"' \
	    cat one.json
	atf_check -o match:'"description":"the blue tables",[^}]*"name":"blue"' \
	    -o match:'"arcana-network-instance:fib":2' cat get.json
	# Not a tunnel, in FIB 0: neither.
	sed 's/{"admin-status"/\n&/g' get.json | grep '"name":"lo0"' > lo0.json
	atf_check -o not-match:'tunnel"' -o not-match:'bind-ni-name' \
	    cat lo0.json
}
yang_tunnel_cleanup()
{
	[ -f gif.name ] && ifconfig "$(cat gif.name)" destroy 2>/dev/null
	cleanup
}

# A route in a vnet jail's routing table 1, whose gateway that table
# alone reaches; one with a source leaves from it; one whose gateway the
# table does not reach is refused, saying so.
FIB_J=arc-tfib

atf_test_case route_fib cleanup
route_fib_head()
{
	atf_set "descr" "A route added in another routing table, its source used"
	atf_set "require.user" "root"
}
route_fib_body()
{
	start_daemon
	atf_check jail -c name=$FIB_J vnet persist path=/ host.hostname=$FIB_J
	ep=$(epair_create)
	echo "$ep" > fib.epair
	atf_check ifconfig "$ep" vnet $FIB_J
	atf_check ifconfig "${ep%a}b" vnet $FIB_J
	atf_check -o ignore jexec $FIB_J sysctl net.fibs=2
	# An address's route in its own table alone, the kernel's default,
	# whatever the host's loader.conf gives a new vnet.
	atf_check -o ignore jexec $FIB_J sysctl net.add_addr_allfibs=0
	atf_check jexec $FIB_J ifconfig "$ep" fib 1
	atf_check jexec $FIB_J ifconfig "$ep" inet 192.0.2.1/24 up
	atf_check jexec $FIB_J ifconfig "$ep" inet 192.0.2.5/32 alias
	atf_check jexec $FIB_J ifconfig "${ep%a}b" inet 192.0.2.2/24 up
	atf_check -o ignore "$JGC" -c "$SOCK" -j $FIB_J -F 1 route add \
	    198.51.100.0/24 192.0.2.2 source 192.0.2.5
	atf_check -o match:"^198\.51\.100\.0/24 +192\.0\.2\.2 +UGS +$ep" \
	    jexec $FIB_J netstat -rn -F 1 -f inet
	atf_check -s not-exit:0 -o ignore -e ignore \
	    jexec $FIB_J route -n get -fib 0 198.51.100.7
	# Out of the far end, from the route's source; seen by bpf(4),
	# which a jail has only where its devfs ruleset shows it.
	[ -c /dev/bpf ] ||
	    atf_skip "no /dev/bpf here: the jail's devfs ruleset hides bpf(4)"
	jexec $FIB_J timeout 10 tcpdump -n -c 1 -i "${ep%a}b" icmp \
	    > td.out 2>/dev/null &
	td=$!
	sleep 1
	jexec $FIB_J setfib 1 ping -c 1 -t 1 198.51.100.7 >/dev/null 2>&1
	wait $td
	atf_check -o match:'IP 192\.0\.2\.5 > 198\.51\.100\.7: ICMP echo request' \
	    cat td.out
	atf_check -s exit:1 -e ignore -o match:'gateway 10\.9\.9\.9 is not reached in routing table 1' \
	    "$JGC" -c "$SOCK" -j $FIB_J -F 1 route add 198.18.0.0/24 10.9.9.9
}
route_fib_cleanup()
{
	if [ -f fib.epair ]; then
		ep=$(cat fib.epair)
		ifconfig "$ep" -vnet $FIB_J 2>/dev/null
		ifconfig "${ep%a}b" -vnet $FIB_J 2>/dev/null
		ifconfig "$ep" destroy 2>/dev/null
	fi
	jail -r $FIB_J 2>/dev/null
	cleanup
}

# Two vnet jails, an underlay and two more epairs between them: a
# geneve tunnel each side made by the agent, traffic through it; and a
# bridge each side over the two epairs, a loop the spanning tree breaks.
L2_A=arc-tla
L2_B=arc-tlb

atf_test_case l2_vnet cleanup
l2_vnet_head()
{
	atf_set "descr" "Geneve tunnels pass traffic, two bridges in a loop have one port discarding"
	atf_set "require.user" "root"
}
l2_vnet_body()
{
	kldload -n if_geneve 2>/dev/null || atf_skip "no if_geneve"
	start_daemon
	for j in $L2_A $L2_B; do
		atf_check jail -c name=$j vnet persist path=/ host.hostname=$j
	done
	: > l2.epairs
	for i in 1 2 3; do
		ep=$(epair_create)
		echo "$ep" >> l2.epairs
		atf_check ifconfig "$ep" vnet $L2_A
		atf_check ifconfig "${ep%a}b" vnet $L2_B
	done
	set -- $(cat l2.epairs)
	atf_check jexec $L2_A ifconfig "$1" inet 192.0.2.1/30 up
	atf_check jexec $L2_B ifconfig "${1%a}b" inet 192.0.2.2/30 up
	# Made, then addressed: up from its making, so it runs.
	atf_check -o match:'done' "$JGC" -c "$SOCK" -j $L2_A geneve geneve0 \
	    create mode l3 id 7 local 192.0.2.1 remote 192.0.2.2
	atf_check -o match:'done' "$JGC" -c "$SOCK" -j $L2_B geneve geneve0 \
	    create mode l3 id 7 local 192.0.2.2 remote 192.0.2.1
	atf_check -o ignore "$JGC" -c "$SOCK" -j $L2_A interface geneve0 add 10.97.0.1/24
	atf_check -o ignore "$JGC" -c "$SOCK" -j $L2_B interface geneve0 add 10.97.0.2/24
	atf_check -o match:'RUNNING' jexec $L2_A ifconfig geneve0
	atf_check -o match:'1 packets received' \
	    jexec $L2_A ping -c 1 -t 5 10.97.0.2
	# The loop: the second and third epairs in a bridge each side.
	for j in $L2_A $L2_B; do
		if [ $j = $L2_A ]; then m2=$2; m3=$3; else m2=${2%a}b; m3=${3%a}b; fi
		atf_check -o ignore "$JGC" -c "$SOCK" -j $j interface bridge0 create
		for c in "set fwddelay 4" "set maxage 6" "addm $m2" "addm $m3" \
		    "flag $m2 stp" "flag $m3 stp"; do
			atf_check -o ignore "$JGC" -c "$SOCK" -j $j bridge bridge0 $c
		done
		atf_check jexec $j ifconfig bridge0 up
	done
	atf_check -s exit:1 -o match:'legacy STP alone' -e ignore \
	    "$JGC" -c "$SOCK" -j $L2_A bridge bridge0 set hellotime 1
	for i in $(seq 1 40); do
		[ "$( (jexec $L2_A ifconfig bridge0; jexec $L2_B ifconfig \
		    bridge0) | grep -c 'state discarding')" -eq 1 ] && break
		sleep 0.5
	done
	atf_check -o inline:'1\n' sh -c "(jexec $L2_A ifconfig bridge0; \
	    jexec $L2_B ifconfig bridge0) | grep -c 'state discarding'"
}
l2_vnet_cleanup()
{
	for j in $L2_A $L2_B; do
		jexec $j ifconfig bridge0 destroy 2>/dev/null
		jexec $j ifconfig geneve0 destroy 2>/dev/null
	done
	if [ -f l2.epairs ]; then
		for ep in $(cat l2.epairs); do
			ifconfig "$ep" -vnet $L2_A 2>/dev/null
			ifconfig "${ep%a}b" -vnet $L2_B 2>/dev/null
			ifconfig "$ep" destroy 2>/dev/null
		done
	fi
	for j in $L2_A $L2_B; do
		jail -r $j 2>/dev/null
	done
	cleanup
}

# A confirmed commit for real: a static route of the candidate made the
# kernel's (FIB 0) and kept in Arcana's rc.conf file; not confirmed, both
# undone at its timeout (arcanactl's session ended long before: the
# persist-id it made keeps the commit); confirmed by its persist-id from
# another session, kept.
atf_test_case commit_route cleanup
commit_route_head()
{
	atf_set "descr" "A confirmed commit of a static route, undone and kept"
	atf_set "require.user" "root"
	atf_set "is.exclusive" "true"
}
commit_route_body()
{
	if route -n get 203.0.113.0 2>/dev/null | grep -q 'destination: 203.0.113.0'; then
		atf_skip "a route to 203.0.113.0 is there already"
	fi
	mkdir -p root/etc/defaults root/usr/local/etc
	cp /etc/defaults/rc.conf root/etc/defaults/
	printf 'hostname="lab"\n' > root/etc/rc.conf
	DAEMON_ARGS="--root $(pwd)/root"
	start_daemon
	"$JGC" -c "$SOCK" get -d running routing > run.json
	sed -e 's|"ietf-ipv4-unicast-routing:ipv4":{}|"ietf-ipv4-unicast-routing:ipv4":{"route":[{"destination-prefix":"203.0.113.0/24","next-hop":{"next-hop-address":"127.0.0.1"}}]}|' \
	    run.json > new.json
	atf_check "$JGC" -c "$SOCK" edit routing @new.json
	atf_check -o match:'^confirm within 3 seconds: arcanactl commit -i [0-9a-f]{32}$' \
	    "$JGC" -c "$SOCK" commit -c 3 -a rc-conf-files
	atf_check -o match:'gateway: 127.0.0.1' route -n get 203.0.113.0
	atf_check -o match:'203.0.113.0/24 127.0.0.1' \
	    cat root/usr/local/etc/rc.conf.d/arcana
	atf_check -o match:'^rc_conf_files=".*/usr/local/etc/rc.conf.d/arcana"' \
	    cat root/etc/rc.conf
	# Not confirmed: undone at its timeout, the kernel's and the file's.
	wait_for "! route -n get 203.0.113.0 | grep -q 'destination: 203.0.113.0' && ! grep -q 203.0.113.0 root/usr/local/etc/rc.conf.d/arcana"
	atf_check -s ignore -o not-match:'destination: 203.0.113.0' -e ignore \
	    route -n get 203.0.113.0
	atf_check -o not-match:'203.0.113.0' cat root/usr/local/etc/rc.conf.d/arcana
	# Confirmed by its persist-id from another session: kept.
	atf_check "$JGC" -c "$SOCK" edit routing @new.json
	atf_check -o match:'commit -i lab$' "$JGC" -c "$SOCK" commit -c 3 -p lab
	atf_check "$JGC" -c "$SOCK" commit -i lab
	sleep 5
	atf_check -o match:'gateway: 127.0.0.1' route -n get 203.0.113.0
}
commit_route_cleanup()
{
	route -n delete -net 203.0.113.0/24 127.0.0.1 >/dev/null 2>&1
	cleanup
}

# A confirmed commit of an interface for real, on a loopback the test
# makes: an address and a description made the kernel's and kept in
# Arcana's rc.conf file (the user's line for it taken out where
# accepted); not confirmed, both undone at its timeout.
atf_test_case commit_interface cleanup
commit_interface_head()
{
	atf_set "descr" "A confirmed commit of an interface's address, undone"
	atf_set "require.user" "root"
	atf_set "is.exclusive" "true"
}
commit_interface_body()
{
	local lo

	lo=$(ifconfig lo create) || atf_fail "no loopback made"
	echo "$lo" > lo.name
	mkdir -p root/etc/defaults root/usr/local/etc
	cp /etc/defaults/rc.conf root/etc/defaults/
	printf 'hostname="lab"\nifconfig_%s="up"\n' "$lo" > root/etc/rc.conf
	DAEMON_ARGS="--root $(pwd)/root"
	start_daemon
	"$JGC" -c "$SOCK" get -d running interfaces > run.json
	sed -e "s|\"name\":\"$lo\"|\"description\":\"lab\",\"name\":\"$lo\",\"ietf-ip:ipv4\":{\"address\":[{\"ip\":\"192.0.2.9\",\"prefix-length\":32}]}|" \
	    run.json > new.json
	atf_check "$JGC" -c "$SOCK" edit interfaces @new.json
	atf_check -o match:'confirm within 3 seconds' \
	    "$JGC" -c "$SOCK" commit -c 3 -a rc-conf-files
	atf_check -o match:'inet 192.0.2.9 netmask 0xffffffff' \
	    -o match:'description: lab' ifconfig "$lo"
	atf_check -o match:"^ifconfig_${lo}_alias0=\"inet 192.0.2.9/32\"" \
	    -o match:"^ifconfig_${lo}_descr=\"lab\"" \
	    cat root/usr/local/etc/rc.conf.d/arcana
	wait_for "! ifconfig $lo | grep -q 192.0.2.9 && ! grep -q lab root/usr/local/etc/rc.conf.d/arcana"
	atf_check -o not-match:'192.0.2.9' -o not-match:'description' \
	    ifconfig "$lo"
	atf_check -o not-match:'192.0.2.9' -o not-match:'lab' \
	    cat root/usr/local/etc/rc.conf.d/arcana
}
commit_interface_cleanup()
{
	[ -s lo.name ] && ifconfig "$(cat lo.name)" destroy 2>/dev/null
	cleanup
}

# A gif made by a confirmed commit, its tunnel ends and an address with
# it, kept in Arcana's rc.conf file (cloned_interfaces, ifconfig_gif57's
# tunnel); not confirmed, destroyed again; confirmed, kept; then taken
# away by a commit of its own.
atf_test_case console_group cleanup
console_group_head()
{
	atf_set "descr" "A local account in the socket's group (-g) is the" \
	    "console: it may name the user it asks for"
	atf_set "require.user" "root"
}
console_group_body()
{
	# A second socket where another account can reach it; its group
	# is nobody's, so nobody is the console there.
	rm -f /tmp/arcana-g57.sock
	echo old > installed-agent
	DAEMON_ARGS="-l unix:/tmp/arcana-g57.sock -g nobody -U $(pwd)/installed-agent"
	start_daemon
	atf_check -o match:'^Host: ' \
	    su -m nobody -c "$JGC -c unix:/tmp/arcana-g57.sock -u admin hello"
	atf_check -o match:'^Host: ' \
	    su -m nobody -c "$JGC -c unix:/tmp/arcana-g57.sock hello"
	# The console, not root: what it installs is signed by the CA, an
	# unsigned program refused and nothing put in place.
	atf_check -s exit:1 -e match:'not signed' -o ignore \
	    su -m nobody -c "$JGC -c unix:/tmp/arcana-g57.sock agent-update $JGD"
	atf_check -o inline:'old\n' cat installed-agent
	kill "$(cat daemon.pid)"
	sleep 0.5
	rm -f /tmp/arcana-g57.sock s.sock
	# Without -g, a local account that names a user is refused.
	DAEMON_ARGS="-l unix:/tmp/arcana-g57.sock"
	start_daemon
	chmod 666 /tmp/arcana-g57.sock
	atf_check -s exit:1 -e match:'may not say whom it asks for' \
	    su -m nobody -c "$JGC -c unix:/tmp/arcana-g57.sock -u admin hello"
}
console_group_cleanup()
{
	rm -f /tmp/arcana-g57.sock
	cleanup
}

atf_test_case onchange_address cleanup
onchange_address_head()
{
	atf_set "descr" "An address added arrives as an on-change patch, told" \
	    "by netlink(4)'s event"
	atf_set "require.user" "root"
}
onchange_address_body()
{
	ifconfig lo57 >/dev/null 2>&1 && atf_skip "lo57 is there already"
	atf_check -o ignore ifconfig lo57 create
	start_daemon
	"$JGC" -c "$SOCK" subscribe -n 2 -o 1 \
	    -x "/ietf-interfaces:interfaces/interface[name='lo57']/ietf-ip:ipv4/address" \
	    > change.out 2>&1 &
	echo $! > sub.pid
	sleep 1.5
	atf_check ifconfig lo57 inet 198.51.100.57/32 alias
	for i in 1 2 3 4 5 6 7 8 9 10; do
		kill -0 "$(cat sub.pid)" 2>/dev/null || break
		sleep 0.5
	done
	atf_check -o match:'^2$' sh -c 'wc -l < change.out | tr -d " "'
	atf_check -o match:'"ietf-yang-push:push-change-update":.*"operation":"create".*198\.51\.100\.57' \
	    tail -1 change.out
}
onchange_address_cleanup()
{
	[ -f sub.pid ] && kill "$(cat sub.pid)" 2>/dev/null
	ifconfig lo57 destroy 2>/dev/null
	cleanup
}

atf_test_case commit_create cleanup
commit_create_head()
{
	atf_set "descr" "A gif made and destroyed by confirmed commits"
	atf_set "require.user" "root"
	atf_set "is.exclusive" "true"
}
commit_create_body()
{
	ifconfig gif57 >/dev/null 2>&1 && atf_skip "gif57 is there already"
	mkdir -p root/etc/defaults root/usr/local/etc
	cp /etc/defaults/rc.conf root/etc/defaults/
	printf 'hostname="lab"\n' > root/etc/rc.conf
	DAEMON_ARGS="--root $(pwd)/root"
	start_daemon
	"$JGC" -c "$SOCK" get -d running interfaces > run.json
	sed -e 's|"interface":\[|"interface":[{"name":"gif57","type":"iana-if-type:tunnel","description":"lab","arcana-interfaces:tunnel":{"local":"192.0.2.1","remote":"192.0.2.2"},"ietf-ip:ipv4":{"address":[{"ip":"198.51.100.57","prefix-length":32,"arcana-interfaces:peer":"198.51.100.58"}]}},|' \
	    run.json > new.json
	atf_check "$JGC" -c "$SOCK" edit interfaces @new.json
	atf_check -o match:'confirm within 3 seconds' \
	    "$JGC" -c "$SOCK" commit -c 3 -a rc-conf-files
	atf_check -o match:'tunnel inet 192.0.2.1 --> 192.0.2.2' \
	    -o match:'inet 198.51.100.57 --> 198.51.100.58 ' \
	    -o match:'description: lab' \
	    -o match:'<UP,' ifconfig gif57
	atf_check -o match:'^cloned_interfaces="gif57"' \
	    -o match:'^ifconfig_gif57="tunnel 192.0.2.1 192.0.2.2 up"' \
	    -o match:'^ifconfig_gif57_alias0="inet 198.51.100.57/32 198.51.100.58"' \
	    cat root/usr/local/etc/rc.conf.d/arcana
	wait_for '! ifconfig gif57 && ! grep -q gif57 root/usr/local/etc/rc.conf.d/arcana'
	atf_check -s not-exit:0 -e ignore ifconfig gif57
	atf_check -o not-match:'gif57' cat root/usr/local/etc/rc.conf.d/arcana
	# Confirmed: kept.
	atf_check "$JGC" -c "$SOCK" edit interfaces @new.json
	atf_check -o match:'commit -i lab$' "$JGC" -c "$SOCK" commit -c 3 -p lab
	atf_check "$JGC" -c "$SOCK" commit -i lab
	sleep 4
	atf_check -o match:'inet 198.51.100.57 ' ifconfig gif57
	# Taken away: off cloned_interfaces, its variables gone.
	atf_check "$JGC" -c "$SOCK" edit interfaces @run.json
	atf_check "$JGC" -c "$SOCK" commit
	atf_check -s not-exit:0 -e ignore ifconfig gif57
	atf_check -o not-match:'gif57' cat root/usr/local/etc/rc.conf.d/arcana
}
commit_create_cleanup()
{
	ifconfig gif57 destroy 2>/dev/null
	cleanup
}

# An interface bound to a network instance by a commit: a loopback made
# in FIB 1 (fib 1 on ifconfig_lo59, SIOCSIFFIB), undone at the timeout.
atf_test_case commit_fib cleanup
commit_fib_head()
{
	atf_set "descr" "An interface made in a FIB by a confirmed commit"
	atf_set "require.user" "root"
	atf_set "is.exclusive" "true"
}
commit_fib_body()
{
	[ "$(sysctl -n net.fibs)" -ge 2 ] || atf_skip "one FIB alone here"
	ifconfig lo59 >/dev/null 2>&1 && atf_skip "lo59 is there already"
	mkdir -p root/etc/defaults root/usr/local/etc
	cp /etc/defaults/rc.conf root/etc/defaults/
	printf 'hostname="lab"\n' > root/etc/rc.conf
	DAEMON_ARGS="--root $(pwd)/root"
	start_daemon
	"$JGC" -c "$SOCK" get -d running interfaces > run.json
	sed -e 's|"interface":\[|"interface":[{"name":"lo59","type":"iana-if-type:softwareLoopback","ietf-network-instance:bind-ni-name":"fib1"},|' \
	    run.json > new.json
	atf_check "$JGC" -c "$SOCK" edit interfaces @new.json
	atf_check -o match:'confirm within 3 seconds' \
	    "$JGC" -c "$SOCK" commit -c 3 -a rc-conf-files
	atf_check -o match:'fib: 1' ifconfig lo59
	atf_check -o match:'^ifconfig_lo59="fib 1 up"' \
	    cat root/usr/local/etc/rc.conf.d/arcana
	atf_check -o match:'bind-ni-name":"fib1"' \
	    "$JGC" -c "$SOCK" get -d running -x \
	    "/ietf-interfaces:interfaces/interface[name='lo59']" interfaces
	wait_for '! ifconfig lo59'
	atf_check -s not-exit:0 -e ignore ifconfig lo59
}
commit_fib_cleanup()
{
	ifconfig lo59 destroy 2>/dev/null
	cleanup
}

# A static route in FIB 1, committed through its network instance's
# vrf-root (RFC 8529, 8528): the kernel's FIB 1 has it, rc.conf too;
# not confirmed, both undone.
atf_test_case commit_fib_route cleanup
commit_fib_route_head()
{
	atf_set "descr" "A FIB's static route committed through its instance's mount"
	atf_set "require.user" "root"
	atf_set "is.exclusive" "true"
}
commit_fib_route_body()
{
	[ "$(sysctl -n net.fibs)" -ge 2 ] || atf_skip "one FIB alone here"
	if route -n get -fib 1 203.0.113.0 2>/dev/null | grep -q 'destination: 203.0.113.0'; then
		atf_skip "FIB 1 has a route to 203.0.113.0 already"
	fi
	mkdir -p root/etc/defaults root/usr/local/etc
	cp /etc/defaults/rc.conf root/etc/defaults/
	printf 'hostname="lab"\n' > root/etc/rc.conf
	DAEMON_ARGS="--root $(pwd)/root"
	start_daemon
	"$JGC" -c "$SOCK" get -d running network-instances > run.json
	# FIB 1's (the first instance's) IPv4 static routes: one; the
	# JSON is one line, and sed changes its first match alone.
	sed -e 's|"ietf-ipv4-unicast-routing:ipv4":{}|"ietf-ipv4-unicast-routing:ipv4":{"route":[{"destination-prefix":"203.0.113.0/24","next-hop":{"next-hop-address":"127.0.0.1"}}]}|' \
	    run.json > new.json
	atf_check -o match:'"name":"fib1"' cat new.json
	atf_check "$JGC" -c "$SOCK" edit network-instances @new.json
	atf_check -o match:'confirm within 3 seconds' \
	    "$JGC" -c "$SOCK" commit -c 3 -a rc-conf-files
	atf_check -o match:'gateway: 127.0.0.1' route -n get -fib 1 203.0.113.0
	atf_check -o match:'203.0.113.0/24 127.0.0.1.*-fib 1|-fib 1.*203.0.113.0/24' \
	    cat root/usr/local/etc/rc.conf.d/arcana
	wait_for "! route -n get -fib 1 203.0.113.0 | grep -q 'destination: 203.0.113.0'"
	atf_check -s ignore -o not-match:'destination: 203.0.113.0' -e ignore \
	    route -n get -fib 1 203.0.113.0
}
commit_fib_route_cleanup()
{
	route -n delete -fib 1 -net 203.0.113.0/24 127.0.0.1 >/dev/null 2>&1
	cleanup
}

# A vnet jail's root (RFC 8530, an inline mount of RFC 8528's), read
# through a helper attached to the jail: its interfaces, and the routes
# of its FIB 1 inside the network instance mounted in it; the host's
# interfaces name the jail of one in it.  The helper killed is started
# again; with the jail it goes, the jail not held dying.
atf_test_case lne_root cleanup
lne_root_head()
{
	atf_set "descr" "A vnet jail's LNE root read through its attached" \
	    "helper: its interfaces and a FIB's routes"
	atf_set "require.user" "root"
}
lne_root_body()
{
	jls -j lne57 >/dev/null 2>&1 && atf_skip "a jail lne57 is there already"
	ifconfig epair57a >/dev/null 2>&1 && atf_skip "epair57a is there already"
	touch mine
	atf_check -o ignore jail -c name=lne57 vnet persist path=/
	[ "$(jexec lne57 sysctl -n net.fibs)" -ge 2 ] ||
	    atf_check -o ignore jexec lne57 sysctl net.fibs=2
	atf_check -o match:'^epair57a$' ifconfig epair57 create
	atf_check ifconfig epair57b vnet lne57
	atf_check jexec lne57 ifconfig epair57b fib 1
	atf_check jexec lne57 ifconfig epair57b inet 198.51.100.57/24 up
	atf_check -o ignore jexec lne57 setfib 1 route -q add -net 203.0.113.0/24 \
	    198.51.100.1
	start_daemon
	atf_check -o save:lne.json "$JGC" -c "$SOCK" get logical-network-elements
	atf_check -o match:'"name":"lne57"' \
	    -o match:'"name":"epair57b"' \
	    -o match:'"ip":"198\.51\.100\.57"' \
	    -o match:'"ietf-yang-library:yang-library"' \
	    -o match:'"vrf-root":\{.*destination-prefix":"203\.0\.113\.0/24"' \
	    cat lne.json
	# Its own helper: every vnet jail on the host has one.
	jid=$(jls -j lne57 jid)
	pid=$(pgrep -P "$(cat daemon.pid)" -f "scope-helper $jid lne-serve")
	[ -n "$pid" ] || atf_fail "no helper of lne57's"
	# The host's: epair57b, bound to lne57.
	atf_check -o match:'"name":"epair57b"[^}]*"ietf-logical-network-element:bind-lne-name":"lne57"' \
	    "$JGC" -c "$SOCK" get interfaces
	atf_check -o match:'"inline":\{\},"label":"root"' \
	    "$JGC" -c "$SOCK" get schema-mounts
	# Killed: started again at the next read.
	atf_check kill -9 "$pid"
	atf_check -o match:'"ip":"198\.51\.100\.57"' \
	    "$JGC" -c "$SOCK" get logical-network-elements
	atf_check -o not-match:"^$pid\$" pgrep -P "$(cat daemon.pid)" -f "scope-helper $jid lne-serve"
	# With the jail, its helper goes: reaped, the jail not held dying.
	# Its interfaces out first: a vnet torn down with an address in it
	# panics a debug kernel.
	atf_check ifconfig epair57a destroy
	atf_check -o ignore jail -r lne57
	sleep 0.5
	atf_check -s not-exit:0 pgrep -P "$(cat daemon.pid)" -f "scope-helper $jid lne-serve"
	atf_check -s not-exit:0 -e match:"not found" jls -d -j lne57 jid
}
lne_root_cleanup()
{
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	if [ -f mine ]; then
		ifconfig epair57a destroy >/dev/null 2>&1
		jail -r lne57 >/dev/null 2>&1
	fi
	cleanup
}

# An epair's two ends as RFC 9408's SAPs, each the other's peer, one in
# a vnet jail; the host's end's status following its link, told to an
# on-change subscription.
atf_test_case yang_sap cleanup
yang_sap_head()
{
	atf_set "descr" "An epair's ends as SAPs, one a vnet jail's; the" \
	    "status following the link down and up, on change"
	atf_set "require.user" "root"
}
yang_sap_body()
{
	local x

	jls -j sap58 >/dev/null 2>&1 && atf_skip "a jail sap58 is there already"
	ifconfig epair58a >/dev/null 2>&1 && atf_skip "epair58a is there already"
	touch mine
	atf_check -o ignore jail -c name=sap58 vnet persist path=/
	atf_check -o match:'^epair58a$' ifconfig epair58 create
	atf_check ifconfig epair58b vnet sap58
	atf_check jexec sap58 ifconfig epair58b up
	atf_check ifconfig epair58a up
	start_daemon
	x="/ietf-network:networks/network[network-id='arcana-sap']/node/ietf-sap-ntw:service/sap"
	atf_check -o match:'"sap-id":"epair58a"' \
	    -o match:'"interface-type":"ietf-sap-ntw:logical"' \
	    -o match:'"peer-sap-id":\["epair58b"\]' \
	    -o match:'"status":"ietf-vpn-common:op-up"' \
	    "$JGC" -c "$SOCK" get -x "$x[sap-id='epair58a']" networks
	atf_check -o match:'"description":"vnet jail sap58"' \
	    -o match:'"peer-sap-id":\["epair58a"\]' \
	    -o match:'"status":"ietf-vpn-common:op-up"' \
	    "$JGC" -c "$SOCK" get -x "$x[sap-id='epair58b']" networks
	atf_check -o match:'"tp-id":"epair58b"' "$JGC" -c "$SOCK" get networks
	# Down: op-down, told as a change of the status alone.
	"$JGC" -c "$SOCK" subscribe -n 2 -o 0 \
	    -x "$x[sap-id='epair58a']/sap-status/status" > change.out 2>&1 &
	echo $! > sub.pid
	sleep 1.5
	atf_check ifconfig epair58a down
	for i in 1 2 3 4 5 6 7 8 9 10; do
		kill -0 "$(cat sub.pid)" 2>/dev/null || break
		sleep 0.5
	done
	atf_check -o match:'^2$' sh -c 'wc -l < change.out | tr -d " "'
	atf_check -o match:'"ietf-vpn-common:op-up"' head -1 change.out
	atf_check -o match:'"ietf-yang-push:push-change-update":.*"operation":"replace".*"ietf-vpn-common:op-down"' \
	    tail -1 change.out
	# Up again.
	atf_check ifconfig epair58a up
	atf_check -o match:'"status":"ietf-vpn-common:op-up"' \
	    "$JGC" -c "$SOCK" get -x "$x[sap-id='epair58a']/sap-status" networks
	# The jail's interfaces out before it goes (a vnet torn down with
	# one in it may panic a debug kernel).
	atf_check ifconfig epair58a destroy
	atf_check -o ignore jail -r sap58
}
yang_sap_cleanup()
{
	[ -f sub.pid ] && kill "$(cat sub.pid)" 2>/dev/null
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	if [ -f mine ]; then
		ifconfig epair58a destroy >/dev/null 2>&1
		jail -r sap58 >/dev/null 2>&1
	fi
	cleanup
}

# An epair's side bound to a vnet jail by commits (bind-lne-name, RFC
# 8530): moved there (SIOCSIFVNET) and kept as the jail's vnet.interface
# in jail.conf; not confirmed, moved back with its address and the file
# as it was; confirmed, and given back by a commit of its own.  Moved
# with more changed at once: refused, lne-assignment-failed.
atf_test_case lne_bind cleanup
lne_bind_head()
{
	atf_set "descr" "An epair moved into a vnet jail and back by commits"
	atf_set "require.user" "root"
	atf_set "is.exclusive" "true"
}
lne_bind_body()
{
	jls -j lne57 >/dev/null 2>&1 && atf_skip "a jail lne57 is there already"
	ifconfig epair57a >/dev/null 2>&1 && atf_skip "epair57a is there already"
	touch mine
	mkdir -p root/etc/defaults root/usr/local/etc
	cp /etc/defaults/rc.conf root/etc/defaults/
	printf 'hostname="lab"\n' > root/etc/rc.conf
	DAEMON_ARGS="--root $(pwd)/root"
	start_daemon
	cat >> etc/jail.conf <<EOF2
lne57 {
	path = "/";
	vnet;
	persist;
}
EOF2
	atf_check -o ignore jail -f etc/jail.conf -c lne57
	atf_check -o match:'^epair57a$' ifconfig epair57 create
	atf_check ifconfig epair57a inet 198.51.100.57/32 alias
	"$JGC" -c "$SOCK" get -d running interfaces > run.json
	atf_check -o match:'"name":"lne57"' \
	    "$JGC" -c "$SOCK" get -d running logical-network-elements
	sed -e 's|"name":"epair57a"|"name":"epair57a","ietf-logical-network-element:bind-lne-name":"lne57"|' \
	    run.json > in.json
	atf_check "$JGC" -c "$SOCK" edit interfaces @in.json
	atf_check -o match:'confirm within 3 seconds' \
	    "$JGC" -c "$SOCK" commit -c 3
	atf_check -s not-exit:0 -e ignore ifconfig epair57a
	atf_check -o match:'^epair57a' ifconfig -j lne57 epair57a
	atf_check -o match:'vnet.interface.*epair57a' cat etc/jail.conf
	atf_check -o match:'"name":"epair57a"[^}]*"ietf-logical-network-element:bind-lne-name":"lne57"' \
	    "$JGC" -c "$SOCK" get -d running interfaces
	# Not confirmed: back, its address with it, jail.conf as it was.
	wait_for "ifconfig epair57a | grep -q 'inet 198.51.100.57 ' && ! grep -q epair57a etc/jail.conf"
	atf_check -o match:'inet 198.51.100.57 ' ifconfig epair57a
	atf_check -o not-match:'epair57a' cat etc/jail.conf
	# Confirmed: kept; then given back by a commit of running without
	# the binding.
	atf_check "$JGC" -c "$SOCK" edit interfaces @in.json
	atf_check "$JGC" -c "$SOCK" commit
	atf_check -o match:'^epair57a' ifconfig -j lne57 epair57a
	"$JGC" -c "$SOCK" get -d running interfaces > bound.json
	sed -e 's|,"ietf-logical-network-element:bind-lne-name":"lne57"||' \
	    bound.json > out.json
	atf_check -o not-match:'bind-lne-name' cat out.json
	atf_check "$JGC" -c "$SOCK" edit interfaces @out.json
	atf_check "$JGC" -c "$SOCK" commit
	atf_check -o match:'^epair57a' ifconfig epair57a
	atf_check -o not-match:'epair57a' cat etc/jail.conf
	# Moved and changed at once: refused.
	sed -e 's|"name":"epair57a"|"name":"epair57a","description":"lab","ietf-logical-network-element:bind-lne-name":"lne57"|' \
	    run.json > both.json
	atf_check "$JGC" -c "$SOCK" edit interfaces @both.json
	atf_check -s not-exit:0 -e match:'moved alone' \
	    "$JGC" -c "$SOCK" commit
	atf_check -o match:'^epair57a' ifconfig epair57a
}
lne_bind_cleanup()
{
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	if [ -f mine ]; then
		ifconfig epair57a destroy >/dev/null 2>&1
		ifconfig -j lne57 epair57a destroy >/dev/null 2>&1
		jail -r lne57 >/dev/null 2>&1
	fi
	cleanup
}

atf_init_test_cases()
{
	atf_add_test_case lne_root
	atf_add_test_case yang_sap
	atf_add_test_case lne_bind
	atf_add_test_case commit_fib_route
	atf_add_test_case commit_fib
	atf_add_test_case console_group
	atf_add_test_case onchange_address
	atf_add_test_case commit_create
	atf_add_test_case commit_interface
	atf_add_test_case commit_route
	atf_add_test_case l2_vnet
	atf_add_test_case route_fib
	atf_add_test_case devd_watch
	atf_add_test_case yang_tunnel
	atf_add_test_case yang_jail_actions
	atf_add_test_case yang_layers
	atf_add_test_case yang_kinds
	atf_add_test_case yang_events
	atf_add_test_case yang_ip
	atf_add_test_case yang_ecmp
	atf_add_test_case yang_static_apply
	atf_add_test_case yang_route_times
	atf_add_test_case yang_rtadv
	atf_add_test_case yang_lne
	atf_add_test_case yang_ni
	atf_add_test_case yang_ni_bind
	atf_add_test_case yang_ni_grow
	atf_add_test_case lifecycle
	atf_add_test_case jail_events_nested
	atf_add_test_case monitors_probe
	atf_add_test_case monitors_fib
	atf_add_test_case stampd_fib
	atf_add_test_case stamp_loss
	atf_add_test_case stamp_delay
	atf_add_test_case stamp_cos
	atf_add_test_case stamp_location
	atf_add_test_case stamp_auth
	atf_add_test_case stamp_unauthenticated
	atf_add_test_case stamp_kinds
	atf_add_test_case monitors_qos
	atf_add_test_case jail_allow_live
	atf_add_test_case jail_dying_namesake
	atf_add_test_case config_files_not_at_boot
	atf_add_test_case jail_base_chflags
	atf_add_test_case live_address
	atf_add_test_case aliases
	atf_add_test_case routes
	atf_add_test_case jail_network
	atf_add_test_case jail_plugins
	atf_add_test_case fw_trace
	atf_add_test_case resnapshot
	atf_add_test_case kmsg
	atf_add_test_case fwmatch_kernel
	atf_add_test_case path_check
	atf_add_test_case crash_event
	atf_add_test_case probe_other_fib
	atf_add_test_case probe_shared_sockets
	atf_add_test_case probe_dscp_packets
	atf_add_test_case sdwan_probe
	atf_add_test_case sdwan_control
	atf_add_test_case sdwan_jail_edge
	atf_add_test_case sdwan_altmark_lab
	atf_add_test_case sdwan_flowexp_lab
	atf_add_test_case sdwan_links
	atf_add_test_case bird_live
	atf_add_test_case sctp_multihome
	atf_add_test_case pkg_lanes
	atf_add_test_case sctp_loopback
	atf_add_test_case sdwan_record
	atf_add_test_case jail_make
	atf_add_test_case zfs_key
	atf_add_test_case carp
}
