#
# make check-html: the page's markup made only of what is escaped.  h_fmt()
# escapes each %s; h_rawf() does not, so each of its %s must be markup of
# this program's: a string literal, a ?: whose every result is one, or
# one of the icons (icon_*).  h_strf() is for what is not markup: its
# format holds no element.  Each format is a literal, for -Wformat and
# for this.
#
#	awk -f check-html.awk src/*.c
#

function fail(what) {
	printf("%s:%d: %s\n", file, at, what) > "/dev/stderr"
	bad++
}

# The text of a string or character literal starting at i: its end.
function skip_lit(s, i,	q, c) {
	q = substr(s, i, 1)
	for (i++; i <= length(s); i++) {
		c = substr(s, i, 1)
		if (c == "\\")
			i++
		else if (c == q)
			return (i)
	}
	return (i)
}

# The call's arguments, from just after its "(", split at the commas
# outside parentheses, brackets, braces and literals: nargs, args[].
function split_call(s, i,	depth, c, start) {
	nargs = 0
	depth = 0
	start = i
	for (; i <= length(s); i++) {
		c = substr(s, i, 1)
		if (c == "\"" || c == "'")
			i = skip_lit(s, i)
		else if (c == "/" && substr(s, i + 1, 1) == "*")
			i = index(substr(s, i + 2), "*/") + i + 2
		else if (c == "(" || c == "[" || c == "{")
			depth++
		else if (c == ")" || c == "]" || c == "}") {
			if (depth == 0) {
				args[++nargs] = substr(s, start, i - start)
				return (i)
			}
			depth--
		} else if (c == "," && depth == 0) {
			args[++nargs] = substr(s, start, i - start)
			start = i + 1
		}
	}
	return (i)
}

function trim(e) {
	gsub(/^[ \t\n]+|[ \t\n]+$/, "", e)
	return (e)
}

# e made of string literals alone: their text joined, or "\001" if not.
function literal(e,	out, i, j, c) {
	e = trim(e)
	out = ""
	if (e == "")
		return ("\001")
	for (i = 1; i <= length(e); i++) {
		c = substr(e, i, 1)
		if (c == " " || c == "\t" || c == "\n")
			continue
		if (c != "\"")
			return ("\001")
		j = skip_lit(e, i)
		out = out substr(e, i + 1, j - i - 1)
		i = j
	}
	return (out)
}

# e this program's markup: a literal, an icon, or a ?: of them.
function trusted(e,	i, c, depth, q, k) {
	e = trim(e)
	while (substr(e, 1, 1) == "(" && substr(e, length(e), 1) == ")" &&
	    closes(e))
		e = trim(substr(e, 2, length(e) - 2))
	if (literal(e) != "\001" || e ~ /^icon_[a-z]+$/)
		return (1)
	# The first ? outside parentheses, then its :.
	depth = 0
	q = 0
	for (i = 1; i <= length(e); i++) {
		c = substr(e, i, 1)
		if (c == "\"" || c == "'")
			i = skip_lit(e, i)
		else if (c == "(" || c == "[")
			depth++
		else if (c == ")" || c == "]")
			depth--
		else if (depth == 0 && c == "?" && q == 0)
			q = i
		else if (depth == 0 && c == "?" && q > 0)
			k++
		else if (depth == 0 && c == ":" && q > 0) {
			if (k > 0) {
				k--
				continue
			}
			return (trusted(substr(e, q + 1, i - q - 1)) &&
			    trusted(substr(e, i + 1)))
		}
	}
	return (0)
}

# The "(" at 1 is closed by the ")" at the end.
function closes(e,	i, c, depth) {
	depth = 0
	for (i = 1; i <= length(e); i++) {
		c = substr(e, i, 1)
		if (c == "\"" || c == "'")
			i = skip_lit(e, i)
		else if (c == "(")
			depth++
		else if (c == ")" && --depth == 0)
			return (i == length(e))
	}
	return (0)
}

function check_call(name, fmt,	n, conv, a, rest, e) {
	if (fmt == "\001") {
		fail(name "() with a format that is not a literal")
		return
	}
	if (name == "h_strf") {
		if (fmt ~ /<[a-zA-Z\/!]/)
			fail("h_strf() making markup: h_fmt() escapes it")
		return
	}
	a = 3
	rest = fmt
	while (match(rest, /%[-+ #0]*(\*|[0-9]+)?(\.(\*|[0-9]+))?(hh|h|ll|l|j|z|t|L|q)?[a-zA-Z%]/)) {
		conv = substr(rest, RSTART, RLENGTH)
		rest = substr(rest, RSTART + RLENGTH)
		if (conv == "%%")
			continue
		n = split(conv, _star, "*") - 1
		a += n
		if (conv ~ /s$/ && !trusted(args[a])) {
			e = trim(args[a])
			gsub(/[ \t\n]+/, " ", e)
			fail("h_rawf()'s %s from " e \
			    ": not this program's markup; h_fmt() escapes it")
		}
		a++
	}
}

# Each file's calls, outside comments, read from their line on: a call
# is shorter than WINDOW lines.
function scan(	i, k, w, p, name, pre) {
	for (i = 1; i <= nl; i++) {
		if (incomment[i] ||
		    !match(line[i], /(^|[^A-Za-z0-9_])h_(rawf|strf)\(/))
			continue
		p = RSTART + (substr(line[i], RSTART, 1) == "h" ? 0 : 1)
		pre = substr(line[i], 1, p - 1)
		if (index(pre, "/*") > 0 && index(pre, "*/") == 0)
			continue
		w = substr(line[i], p)
		for (k = i + 1; k <= nl && k < i + WINDOW; k++)
			w = w "\n" line[k]
		name = substr(w, 1, 6)
		split_call(w, 8)
		if (args[1] ~ /struct html/)
			continue
		at = i
		check_call(name, literal(args[2]))
	}
}

BEGIN {
	WINDOW = 60
}
FNR == 1 && NR > 1 {
	scan()
	nl = 0
	c = 0
}
{
	file = FILENAME
	line[++nl] = $0
	incomment[nl] = c || $0 ~ /^[ \t]*\/?\*/
	if (index($0, "/*") > 0)
		c = 1
	if (index($0, "*/") > 0)
		c = 0
}
END {
	scan()
	if (bad > 0)
		exit 1
	print "www/arcana-ui: h_rawf()'s and h_strf()'s calls are as they must be"
}

