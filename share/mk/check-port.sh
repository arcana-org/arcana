#!/bin/sh
#
# make check-port: the port's submodule tuples (GH_TUPLE in
# port/sysutils/arcana/Makefile) at the commits the tree pins its
# submodules to (git submodule status).  Outside a git checkout (a
# release's tarball, the port's own build) there is nothing to compare.
#
#	sh check-port.sh <top of the tree>
#

top=${1:?the top of the tree}
mk=$top/port/sysutils/arcana/Makefile

if ! git -C "$top" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
	echo "port: no git checkout here, its tuples not compared"
	exit 0
fi
# "account:project:commit:group/path", one a line.
tuples=$(sed -n -e '/^GH_TUPLE=/,/[^\\]$/p' "$mk" | tr -d '\\' |
    sed -e 's/^GH_TUPLE=//' | tr -s ' \t' '\n' | grep -v '^$')
[ -n "$tuples" ] || { echo "$mk: no GH_TUPLE" >&2; exit 1; }
bad=0
for t in $tuples; do
	commit=$(echo "$t" | cut -d: -f3)
	path=${t##*/}
	pin=$(git -C "$top" submodule status -- "$path" 2>/dev/null |
	    sed -e 's/^[-+ U]//' | cut -d' ' -f1)
	if [ -z "$pin" ]; then
		echo "$mk: $path is no submodule of the tree" >&2
		bad=1
	elif [ "$pin" != "$commit" ]; then
		echo "$mk: $path at $commit, the tree's submodule at $pin" >&2
		bad=1
	fi
done
# And every submodule the port builds from its tuples, but cblink,
# which the port takes from devel/cblink.
for path in $(git -C "$top" config -f .gitmodules --get-regexp \
    '^submodule\..*\.path$' | cut -d' ' -f2); do
	[ "$path" = cblink ] && continue
	echo "$tuples" | grep -q "/$path\$" || {
		echo "$mk: no GH_TUPLE for the submodule $path" >&2
		bad=1
	}
done
[ $bad -eq 0 ] || { echo "port: update GH_TUPLE, then make makesum" >&2;
    exit 1; }
echo "port: its tuples are the tree's submodules"
