# Every top-level node and every action and rpc of the console's own
# module (share/yang/arcana-console@*.yang) has a row in the one table
# of who may touch it (www/arcana-console/cnodes.c), and the table names
# none the module has not.
#
#	awk -f cnodes.awk www/arcana-console/cnodes.c \
#	    share/yang/arcana-console@*.yang
#
# A node is named by the containers and lists down to it, a list's key
# left out (hosts/host/move); a table's row, CD "..." or CO "...", the
# same with each =* taken out.  Prints each node without a row and each
# row without a node; exits 1 for either.

FNR == 1 { file++; d = 0 }

# The table's rows.
file == 1 && /\{ (CD|CO) "/ {
	s = $0
	sub(/^.*\{ (CD|CO) "/, "", s)
	sub(/".*$/, "", s)
	gsub(/=\*/, "", s)
	row[s] = 1
	next
}
file == 1 { next }

# The module's nodes: a name stack by braces.
{
	line = $0
	sub(/\/\/.*/, "", line)
	opened = 0
	if (match(line, /^ *(container|list|action|rpc|anydata|anyxml|leaf|leaf-list|grouping|augment|notification|choice|case|input|output) /)) {
		s = line
		sub(/^ +/, "", s)
		split(s, w, /[ {;]+/)
		kind = w[1]
		name = (kind == "input" || kind == "output") ? kind : w[2]
		if (d == 0 && kind != "grouping" && kind != "augment" &&
		    kind != "notification")
			top = 1
		if (line ~ /\{/) {
			stack[++d] = name
			kinds[d] = kind
			opened = 1
		}
		# A node of the module's top (d 2: in module { }): every one;
		# below it, each action and rpc.
		if (d == 2 && (kind == "container" || kind == "list" ||
		    kind == "anydata" || kind == "anyxml" || kind == "leaf" ||
		    kind == "rpc") || (kind == "action" && ingrouping() == 0)) {
			p = ""
			for (i = 2; i <= d; i++)
				if (stack[i] != "-" && kinds[i] != "choice" &&
				    kinds[i] != "case")
					p = p (p == "" ? "" : "/") stack[i]
			if (opened == 0)
				p = p (p == "" ? "" : "/") name
			node[p] = 1
		}
	}
	n = gsub(/\{/, "{", line)
	m = gsub(/\}/, "}", line)
	n -= opened
	for (i = 0; i < n; i++) {
		stack[++d] = "-"
		kinds[d] = "-"
	}
	for (i = 0; i < m; i++)
		d--
}

function ingrouping(	i) {
	for (i = 1; i <= d; i++)
		if (kinds[i] == "grouping")
			return (1)
	return (0)
}

END {
	bad = 0
	for (p in node)
		if (!(p in row)) {
			printf("cnodes.c: no row for arcana-console:%s\n", p)
			bad = 1
		}
	for (p in row)
		if (!(p in node)) {
			printf("cnodes.c: a row for arcana-console:%s, which the "\
			    "module has not\n", p)
			bad = 1
		}
	exit (bad)
}
