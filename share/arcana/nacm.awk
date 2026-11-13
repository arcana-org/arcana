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
#
# The same of the data a read gives out: a leaf that holds the text of a
# file or a command line (named text, argv, args, cmdline, command,
# config, content or options, the module's state, an output or a
# notification, not an input) is nacm:default-deny-all, itself or
# beneath a node that is, or is named in the list as <module>:<path>
# (the path as an operation's, then the leaf's name) with what is done
# of its secrets (masked below an operator: wmask()), or why it has
# none.
#
#	awk -v out=h -f nacm.awk nacm-allow share/yang/arcana-*.yang
#
# writes, the same checks passing, the allow-list's actions and rpcs of
# the agent's modules as NACM rules' module and data-node path, for the
# console's nacm-sync (www/arcana-console/ytrans.c, nacmallow.h): an
# augment's target by its modules' names, the module's own node after
# it named by its module.

# Leaves whose text may be a file's or a command line's.
function texty(s) {
	return (s ~ /^(text|argv|args|cmdline|command|config|content|options)$/)
}

# Is a node from depth 1 to d nacm:default-deny-all?
function denied_at(d,	i) {
	for (i = 1; i <= d; i++)
		if (deny[i])
			return (1)
	return (0)
}

# Path p of module m whose first step is a grouping's: the paths where
# its uses put it ("|" before each), a grouping's within a grouping
# followed, none that uses itself.
function expand(m, p, lvl,	g, rest, ns, s, j, r, w) {
	g = p
	sub(/^\//, "", g)
	sub(/\/.*/, "", g)
	if (lvl > 4)
		return ("")
	rest = substr(p, length(g) + 2)
	ns = split(sites[m SUBSEP g], s, "|")
	r = ""
	for (j = 2; j <= ns; j++) {
		w = substr(s[j], 2)
		if (substr(s[j], 1, 1) == "C")
			r = r "|" w rest
		else if (index(w "/", "/" g "/") == 0)
			r = r expand(m, w rest, lvl + 1)
	}
	return (r)
}

# Operation o (<module>:<path>) as a NACM data-node path: each step
# named by its module, the prefixes of an augment's target its imports'.
function datapath(o,	m, p, n, seg, i, out, pfx, own) {
	m = o
	sub(/:.*/, "", m)
	p = o
	sub(/^[^:]*:/, "", p)
	sub(/^\/+/, "", p)
	n = split(p, seg, "/")
	out = ""
	own = 0
	for (i = 1; i <= n; i++) {
		if (seg[i] ~ /:/) {
			pfx = seg[i]
			sub(/:.*/, "", pfx)
			if (!((m SUBSEP pfx) in pmap)) {
				printf("%s: no module of prefix %s\n", o, pfx) \
				    > "/dev/stderr"
				bad = 1
			}
			sub(/^[^:]*:/, pmap[m SUBSEP pfx] ":", seg[i])
			out = out "/" seg[i]
		} else if (!own) {
			out = out "/" m ":" seg[i]
			own = 1
		} else
			out = out "/" seg[i]
	}
	return (out)
}

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
	input = 0
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
			kind[depth] = stkw
			deny[depth] = 0
			leaf[depth] = ""
			if (stkw ~ /^(container|list|grouping|augment|action|rpc)$/)
				name[depth] = starg
			if ((stkw == "leaf" || stkw == "leaf-list") && texty(starg))
				leaf[depth] = starg
			if (stkw == "input" && input == 0)
				input = depth
			if (stkw == "import")
				imp[depth] = starg
			if (stkw == "grouping")
				groupings[mod SUBSEP starg] = 1
			if ((stkw == "action" || stkw == "rpc") && op == 0) {
				op = depth
				opname = mod ":" path()
				ops[opname] = 1
				for (k = 1; k < depth; k++)
					if (kind[k] == "grouping")
						grouped[opname] = 1
			}
		} else if (c == ";") {
			statement()
			if (stkw == "prefix" && kind[depth] == "import")
				pmap[mod SUBSEP starg] = imp[depth]
			# Where a grouping is used: within another grouping
			# (G) or in the module's data (C).
			if (stkw == "uses") {
				gk = "C"
				for (k = 1; k <= depth; k++)
					if (kind[k] == "grouping")
						gk = "G"
				sites[mod SUBSEP starg] = sites[mod SUBSEP \
				    starg] "|" gk path()
			}
			if (op > 0 && depth == op && stkw == "nacm:default-deny-all")
				denied[opname] = 1
			if (stkw == "nacm:default-deny-all")
				deny[depth] = 1
		} else if (c == "}") {
			word = ""
			if (leaf[depth] != "" && input == 0 &&
			    !denied_at(depth)) {
				tn = mod ":" path() "/" leaf[depth]
				texts[tn] = 1
			}
			if (depth == input)
				input = 0
			if (depth == op)
				op = 0
			depth--
		} else
			word = word c
	}
	word = word "\n"
}

END {
	for (t in texts) {
		m = t
		sub(/:.*/, "", m)
		if (!(t in allow) && !((m ":*") in allow)) {
			printf("%s: a file's or a command line's text, " \
			    "neither nacm:default-deny-all nor in " \
			    "share/arcana/nacm-allow\n", t)
			bad = 1
		}
	}
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
		if (a ~ /:\*$/ ? !(m in mods) : !(a in ops) && !(a in texts)) {
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
	if (out != "h" || bad)
		exit (bad)
	# The allow-list's operations, sorted: their permits.
	n = 0
	for (a in allow) {
		if (!(a in ops) || (a in denied))
			continue
		# In a grouping: a permit where each of its uses puts it.
		m = a
		sub(/:.*/, "", m)
		p = substr(a, length(m) + 2)
		ns = split((a in grouped) ? expand(m, p, 0) : "|" p, site, "|")
		k = 0
		for (j = 2; j <= ns; j++)
			if (site[j] != "") {
				v[++n] = m ":" site[j]
				k++
			}
		if (k == 0) {
			printf("%s: in a grouping, no data-node path for its " \
			    "permit\n", a) > "/dev/stderr"
			exit (1)
		}
	}
	for (i = 2; i <= n; i++)
		for (k = i; k > 1 && v[k - 1] > v[k]; k--) {
			t = v[k]
			v[k] = v[k - 1]
			v[k - 1] = t
		}
	print "/* Written by share/arcana/nacm.awk from share/arcana/nacm-allow: */"
	print "/* the actions and rpcs the agents run by NACM's exec-default, */"
	print "/* each its module and its data-node path. */"
	print "#define\tNACM_ALLOW_RULES { \\"
	for (i = 1; i <= n; i++) {
		m = v[i]
		sub(/:.*/, "", m)
		printf("\t{ \"%s\", \"%s\" }, \\\n", m, datapath(v[i]))
	}
	print "}"
	exit (bad)
}
