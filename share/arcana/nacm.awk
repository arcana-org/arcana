# Every action and rpc of Arcana's modules (share/yang/arcana-*.yang),
# each either nacm:default-deny-all or named in the allow-list
# (share/arcana/nacm-allow) with why it may run by NACM's exec-default:
# it only reads, and gives out nothing that should stay on the host.
# What changes the host, runs a program with arguments its caller
# chooses, makes the host connect out or gives out a secret is marked.
#
#	awk -f nacm.awk nacm-allow share/yang/arcana-*.yang
#
# An operation is named <module>:<path>, the path the names of the
# containers, lists, groupings and augments around it then its own
# (arcana-services:/services/service/start); "<module>:*" in the list
# is the whole module's, one served by another program than the agent.
# Prints each operation that is neither, and one the list names that no
# module has; exits 1 for either.

function strip(s) {
	sub(/^[ \t\n]+/, "", s)
	sub(/[ \t\n]+$/, "", s)
	return (s)
}

function path(	i, p) {
	p = ""
	for (i = 1; i <= depth; i++)
		if (name[i] != "")
			p = p "/" name[i]
	return (p)
}

# A statement's keyword and argument, at its "{" or ";".
function statement(	kw, arg) {
	word = strip(word)
	kw = word
	sub(/[ \t\n].*/, "", kw)
	arg = word
	sub(/^[^ \t\n]+[ \t\n]*/, "", arg)
	gsub(/"/, "", arg)
	stkw = kw
	starg = arg
	word = ""
}

# The allow-list: "<module>:<path>" then its reason, a tab between.
FILENAME == ARGV[1] {
	if ($0 ~ /^#/ || $0 ~ /^[ \t]*$/)
		next
	split($0, f, "\t")
	if (strip(f[2]) == "") {
		printf("%s: %s: no reason given\n", FILENAME, f[1])
		bad = 1
	}
	allow[f[1]] = 1
	next
}

FNR == 1 {
	mod = FILENAME
	sub(/.*\//, "", mod)
	sub(/@.*/, "", mod)
	depth = 0
	op = 0
	quote = ""
	word = ""
	mods[mod] = 1
}

{
	n = split($0, ch, "")
	for (i = 1; i <= n; i++) {
		c = ch[i]
		if (quote != "") {
			word = word c
			if (quote == "\"" && c == "\\")
				word = word ch[++i]
			else if (c == quote)
				quote = ""
			continue
		}
		if (c == "\"" || c == "'") {
			quote = c
			word = word c
		} else if (c == "/" && ch[i + 1] == "/")
			break
		else if (c == "{") {
			statement()
			depth++
			name[depth] = ""
			if (stkw ~ /^(container|list|grouping|augment|action|rpc)$/)
				name[depth] = starg
			if ((stkw == "action" || stkw == "rpc") && op == 0) {
				op = depth
				opname = mod ":" path()
				ops[opname] = 1
			}
		} else if (c == ";") {
			statement()
			if (op > 0 && depth == op && stkw == "nacm:default-deny-all")
				denied[opname] = 1
		} else if (c == "}") {
			word = ""
			if (depth == op)
				op = 0
			depth--
		} else
			word = word c
	}
	word = word "\n"
}

END {
	for (o in ops) {
		m = o
		sub(/:.*/, "", m)
		if (!(o in denied) && !(o in allow) && !((m ":*") in allow)) {
			printf("%s: neither nacm:default-deny-all nor in " \
			    "share/arcana/nacm-allow\n", o)
			bad = 1
		}
	}
	for (a in allow) {
		m = a
		sub(/:.*/, "", m)
		if (a ~ /:\*$/ ? !(m in mods) : !(a in ops)) {
			printf("share/arcana/nacm-allow: %s: no such operation\n",
			    a)
			bad = 1
		}
		if (a in denied) {
			printf("share/arcana/nacm-allow: %s: marked " \
			    "nacm:default-deny-all already\n", a)
			bad = 1
		}
	}
	exit (bad)
}
