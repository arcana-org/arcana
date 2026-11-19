/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The host's network storage services, the base system's: the NFS
 * server, NFSv4 alone (nfsd(8) with nfsv4_server_only, mountd(8) for
 * the exports, no NFSv3 and no rpcbind; exports(5) with its V4: root,
 * a directory on ZFS; the datasets that share themselves by sharenfs,
 * zfsprops(7), which zfs writes to /etc/zfs/exports for mountd; NFSv4.2
 * by vfs.nfsd.server_max_minorversion, pNFS by nfsd's -p and -m, as
 * pnfsserver(4) has it), the iSCSI target (ctld(8), ctl.conf(5),
 * ctladm(8)) and HAST (hastd(8), hast.conf(5), hastctl(8)).  Read
 * whole (the netstore operation), changed by jobs of the nfs, iscsi and
 * hast kinds.  ctl.conf's CHAP secrets are read as a marker, and kept
 * where a write gives the marker back.  A HAST resource whose local
 * provider is the system's (storage_protected()) is neither created nor
 * given a role.
 *
 * The NFS server of a vnet jail too, jail(8)'s allow.nfsd: nfsd(8),
 * mountd(8) and nfsuserd(8) run in the jail, by its own rc.conf (sysrc
 * -j) and rc.d (service(8) by jexec(8)), serving its own exports(5),
 * written beneath its root and never through a link out of it.  There
 * nfsd serves over TCP alone and without pNFS (nfsd(8)), and a dataset's
 * sharenfs is the host's (zfs writes the host's /etc/zfs/exports, for
 * the host's mountd): a jail exports by its exports(5) alone, its V4:
 * root a directory on ZFS as the jail sees it.  A jail without a
 * network of its own, without allow.nfsd or with enforce_statfs 0 is
 * refused, saying what to set.  The iSCSI target and HAST are the
 * host's alone: ctl(4) and GEOM are not a jail's.
 */

#include <sys/param.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysctl.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <jail.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ucl.h>

#include "agent.h"

#define	TEXT_MAX	(256 * 1024)

/* Why the iSCSI target and HAST are never a jail's. */
#define	ISCSI_HOSTS	"ctld(8) serves the kernel's CAM target layer " \
	"(ctl(4)), which no jail has; set the iSCSI target on the host"
#define	HAST_HOSTS	"hastd(8) replicates GEOM providers and makes " \
	"/dev/hast/*, which no jail has; set HAST on the host"

static void
put_s(ucl_object_t *o, const char *k, const char *v)
{

	if (v != NULL)
		ucl_object_insert_key(o, ucl_object_fromstring(v), k, 0, true);
}

static void
put_b(ucl_object_t *o, const char *k, bool v)
{

	ucl_object_insert_key(o, ucl_object_frombool(v), k, 0, true);
}

static char *
slurp(struct work *w, const char *path)
{
	FILE	*fp;
	char	*buf;
	size_t	 n;

	if ((fp = fopen(path, "re")) == NULL)
		return (NULL);
	buf = wcalloc(w, TEXT_MAX + 1, 1);
	n = fread(buf, 1, TEXT_MAX, fp);
	fclose(fp);
	buf[n] = '\0';
	return (buf);
}

/* A file of the system's, written whole: a new one moved over it, with
 * the mode given (ctl.conf may hold CHAP secrets). */
static int
put_file(struct work *w, const char *path, const char *text, mode_t mode,
    const char **errp)
{
	const char	*tmp;
	int		 fd;
	size_t		 len;

	tmp = wfmt(w, "%s.arcana-new", path);
	len = strlen(text);
	if ((fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC |
	    O_NOFOLLOW, mode)) == -1 || fchmod(fd, mode) != 0 || write(fd, text,
	    len) != (ssize_t)len || fsync(fd) != 0) {
		*errp = wfmt(w, "%s: %s", path, strerror(errno));
		if (fd != -1)
			(void)close(fd);
		(void)unlink(tmp);
		return (-1);
	}
	/* Closed once: a failed close or rename closes no other thread's. */
	if (close(fd) != 0 || rename(tmp, path) != 0) {
		*errp = wfmt(w, "%s: %s", path, strerror(errno));
		(void)unlink(tmp);
		return (-1);
	}
	return (0);
}

/* A text a file of the system's is given: printable lines, no NUL. */
static bool
text_ok(const char *t)
{
	const unsigned char	*p;

	if (t == NULL || strlen(t) > TEXT_MAX)
		return (false);
	for (p = (const unsigned char *)t; *p != '\0'; p++)
		if (*p < 0x20 && *p != '\n' && *p != '\t' && *p != '\r')
			return (false);
	return (true);
}

/*
 * ctl.conf(5)'s CHAP secrets, in either of its forms: the classic one
 * ("chap user secret", "chap-mutual user secret muser msecret") and
 * UCL's (secret and mutual-secret beside user and mutual-user, in an
 * object of a chap or chap-mutual list).  A read gives the text with
 * each secret the marker, which the console's viewers see in its place;
 * a write that gives the marker back keeps the secret the file has for
 * the same place: the blocks around it, the kind, and its users.
 */
#define	SECRET_MARK	"\"********\""

enum { T_WORD, T_STR, T_PUNCT };

struct ctok {
	size_t	 off, len;	/* in the text, quotes and all */
	int	 type;
	int	 depth;		/* of the { } and [ ] around it */
	int	 open;		/* the token that opened its block; -1 */
	bool	 used;		/* taken by a chap line */
};

/* A token's value: a word, or a string without its quotes. */
static char *
ctok_val(struct work *w, const char *text, const struct ctok *t)
{

	if (t->type == T_STR)
		return (wstrndup(w, text + t->off + 1, t->len >= 2 ? t->len - 2 :
		    0));
	return (wstrndup(w, text + t->off, t->len));
}

static bool
ctok_is(const char *text, const struct ctok *t, const char *s)
{
	size_t	n;

	n = strlen(s);
	if (t->type == T_STR)
		return (t->len == n + 2 && memcmp(text + t->off + 1, s, n) == 0);
	return (t->type == T_WORD && t->len == n && memcmp(text + t->off, s, n) ==
	    0);
}

/*
 * Is text[i] punctuation, a token of its own?  { } ; = always; [ only
 * where UCL opens a list (after =, a key and its ':', a [ or a ','), ]
 * and ',' only in such a list; ':' never (UCL's "key:" is a word that
 * ends in it).
 */
static bool
ctl_punct(const char *text, size_t i, const struct ctok *v, int n,
    bool inlist)
{
	const struct ctok	*p;
	char			 c;

	if (strchr("{};=", text[i]) != NULL)
		return (true);
	if ((text[i] == ']' || text[i] == ',') && inlist)
		return (true);
	if (text[i] != '[' || n == 0)
		return (false);
	p = &v[n - 1];
	c = text[p->off + p->len - 1];
	return ((p->type == T_PUNCT && strchr("=[,", c) != NULL) ||
	    (p->type == T_WORD && c == ':'));
}

/* The text's tokens; comments (#, //, slash-star) are none. */
static struct ctok *
ctl_tokens(struct work *w, const char *text, int *np)
{
	struct ctok	*v;
	size_t		 i, len, cap;
	int		 n, depth, stack[64];
	char		 q;

	len = strlen(text);
	cap = 64;
	v = wcalloc(w, cap, sizeof(*v));
	n = depth = 0;
	for (i = 0; i < len;) {
		if (isspace((unsigned char)text[i])) {
			i++;
			continue;
		}
		if (text[i] == '#' || (text[i] == '/' && text[i + 1] == '/')) {
			i += strcspn(text + i, "\n");
			continue;
		}
		if (text[i] == '/' && text[i + 1] == '*') {
			const char *e = strstr(text + i + 2, "*/");

			i = e != NULL ? (size_t)(e - text) + 2 : len;
			continue;
		}
		if ((size_t)n == cap) {
			struct ctok *nv = wcalloc(w, cap * 2, sizeof(*v));

			memcpy(nv, v, cap * sizeof(*v));
			v = nv;
			cap *= 2;
		}
		v[n].off = i;
		v[n].used = false;
		v[n].open = depth > 0 ? stack[depth - 1] : -1;
		if (text[i] == '"' || text[i] == '\'') {
			q = text[i++];
			while (i < len && text[i] != q) {
				if (text[i] == '\\' && i + 1 < len)
					i++;
				i++;
			}
			if (i < len)
				i++;
			v[n].type = T_STR;
		} else if (ctl_punct(text, i, v, n, depth > 0 && text[v[stack[
		    depth - 1]].off] == '[')) {
			if ((text[i] == '}' || text[i] == ']') && depth > 0)
				depth--;
			v[n].open = depth > 0 ? stack[depth - 1] : -1;
			v[n].type = T_PUNCT;
			i++;
		} else {
			/* The classic form's words have ':' and '[ ]' in them
			 * (an iqn name, [::1]:3260): braces, ;, =, quotes and #
			 * end one. */
			while (i < len && !isspace((unsigned char)text[i]) &&
			    strchr("{};=\"'#", text[i]) == NULL && (text[i] != ','
			    || depth == 0 || text[v[stack[depth - 1]].off] != '[') &&
			    (text[i] != ']' || depth == 0 || text[v[stack[depth -
			    1]].off] != '['))
				i++;
			v[n].type = T_WORD;
		}
		v[n].len = i - v[n].off;
		v[n].depth = depth;
		if (v[n].type == T_PUNCT && (text[v[n].off] == '{' ||
		    text[v[n].off] == '[')) {
			if (depth == (int)nitems(stack))
				return (NULL);
			stack[depth++] = n;
		}
		n++;
	}
	*np = n;
	return (v);
}

/*
 * Block b's name: UCL's key before its = or ':' (or the key that ends
 * in ':'), or the classic form's words before it since the statement
 * before (auth-group ag0, target iqn...).
 */
static const char *
ctl_label(struct work *w, const char *text, const struct ctok *v, int b)
{
	const char	*l;
	char		 c;
	int		 k;

	if (b > 0 && v[b - 1].type == T_PUNCT && text[v[b - 1].off] == '=')
		return (b > 1 && v[b - 2].type != T_PUNCT ? ctok_val(w, text,
		    &v[b - 2]) : "");
	if (b > 0 && v[b - 1].type == T_WORD && (c = text[v[b - 1].off +
	    v[b - 1].len - 1]) == ':') {
		if (v[b - 1].len == 1)
			return (b > 1 && v[b - 2].type != T_PUNCT ? ctok_val(w,
			    text, &v[b - 2]) : "");
		return (wstrndup(w, text + v[b - 1].off, v[b - 1].len - 1));
	}
	for (k = b - 1; k >= 0 && v[k].type != T_PUNCT; k--)
		;
	l = "";
	for (k++; k < b; k++)
		l = wfmt(w, "%s%s%s", l, l[0] != '\0' ? " " : "", ctok_val(w,
		    text, &v[k]));
	return (l);
}

/* Where token i is: the labels of the blocks around it, outermost first. */
static const char *
ctl_path(struct work *w, const char *text, const struct ctok *v, int i)
{
	const char	*p;
	int		 b;

	p = "";
	for (b = v[i].open; b != -1; b = v[b].open)
		p = wfmt(w, "%s{%s}", ctl_label(w, text, v, b), p);
	return (p);
}

/* Is t UCL's key s: the word, "s", or s: */
static bool
ctok_key(const char *text, const struct ctok *t, const char *s)
{
	size_t	n;

	n = strlen(s);
	return (ctok_is(text, t, s) || (t->type == T_WORD && t->len == n + 1 &&
	    memcmp(text + t->off, s, n) == 0 && text[t->off + n] == ':'));
}

/* The token of key k's value (after its = or ':', if any); -1 for none. */
static int
ctl_value(const char *text, const struct ctok *v, int n, int k)
{

	if (!(v[k].type == T_WORD && text[v[k].off + v[k].len - 1] == ':') &&
	    k + 1 < n && ((v[k + 1].type == T_PUNCT && text[v[k + 1].off] ==
	    '=') || (v[k + 1].type == T_WORD && v[k + 1].len == 1 &&
	    text[v[k + 1].off] == ':')))
		k++;
	return (k + 1 < n && v[k + 1].type != T_PUNCT ? k + 1 : -1);
}

/* The value of key in the object opened at b (at its own level); NULL. */
static const char *
ctl_member(struct work *w, const char *text, const struct ctok *v, int n,
    int b, const char *key)
{
	int	k, x;

	for (k = b + 1; k < n && v[k].depth > v[b].depth; k++)
		if (v[k].open == b && v[k].type != T_PUNCT && ctok_key(text,
		    &v[k], key) && (x = ctl_value(text, v, n, k)) != -1)
			return (ctok_val(w, text, &v[x]));
	return (NULL);
}

struct csecret {
	const char	*where;		/* path, kind and users */
	size_t		 off, len;	/* the secret's token */
};

/* The secrets of text, each with where it is; *np of them; NULL when the
 * text cannot be read as either form. */
static struct csecret *
ctl_secrets(struct work *w, const char *text, int *np)
{
	struct csecret	*s;
	struct ctok	*v;
	const char	*u, *mu;
	int		 n, i, m, k;
	bool		 sec;

	if ((v = ctl_tokens(w, text, &n)) == NULL)
		return (NULL);
	s = wcalloc(w, (size_t)n + 1, sizeof(*s));
	m = 0;
	for (i = 0; i < n; i++) {
		if (v[i].used || v[i].type == T_PUNCT)
			continue;
		/* The classic form: chap user secret. */
		if ((ctok_is(text, &v[i], "chap") || ctok_is(text, &v[i],
		    "chap-mutual")) && i + 2 < n && v[i + 1].type != T_PUNCT &&
		    v[i + 2].type != T_PUNCT) {
			bool mutual = ctok_is(text, &v[i], "chap-mutual");

			u = ctok_val(w, text, &v[i + 1]);
			s[m].where = wfmt(w, "%s|chap|%s", ctl_path(w, text, v,
			    i), u);
			s[m].off = v[i + 2].off;
			s[m++].len = v[i + 2].len;
			v[i + 1].used = v[i + 2].used = true;
			if (mutual && i + 4 < n && v[i + 3].type != T_PUNCT &&
			    v[i + 4].type != T_PUNCT) {
				mu = ctok_val(w, text, &v[i + 3]);
				s[m].where = wfmt(w, "%s|mutual|%s|%s", ctl_path(w,
				    text, v, i), u, mu);
				s[m].off = v[i + 4].off;
				s[m++].len = v[i + 4].len;
				v[i + 3].used = v[i + 4].used = true;
			}
			continue;
		}
		/* UCL's: secret = "...", its users beside it. */
		if ((!(sec = ctok_key(text, &v[i], "secret")) && !ctok_key(text,
		    &v[i], "mutual-secret")) || v[i].open == -1 || (k =
		    ctl_value(text, v, n, i)) == -1)
			continue;
		u = ctl_member(w, text, v, n, v[i].open, "user");
		mu = ctl_member(w, text, v, n, v[i].open, "mutual-user");
		s[m].where = wfmt(w, "%s|%s|%s|%s", ctl_path(w, text, v, i), sec ?
		    "chap" : "mutual", u != NULL ? u : "", mu != NULL && !sec ?
		    mu : "");
		s[m].off = v[k].off;
		s[m++].len = v[k].len;
		v[k].used = true;
	}
	*np = m;
	return (s);
}

/* text with every CHAP secret the marker. */
static const char *
ctl_masked(struct work *w, const char *text)
{
	struct csecret	*s;
	const char	*out;
	size_t		 at;
	int		 n, i;

	if ((s = ctl_secrets(w, text, &n)) == NULL)
		return ("# not shown: ctl.conf could not be read for its "
		    "secrets\n");
	out = "";
	at = 0;
	for (i = 0; i < n; i++) {
		out = wfmt(w, "%s%.*s%s", out, (int)(s[i].off - at), text + at,
		    SECRET_MARK);
		at = s[i].off + s[i].len;
	}
	return (wfmt(w, "%s%s", out, text + at));
}

/*
 * text as it is written: each marker given back replaced by the secret
 * the file has (was) in the same place.  NULL, with why, when one has
 * none there, or two of the same place.
 */
static const char *
ctl_unmasked(struct work *w, const char *text, const char *was,
    const char **errp)
{
	struct csecret	*s, *o;
	const char	*out;
	size_t		 at;
	int		 n, no, i, k, hit;

	if ((s = ctl_secrets(w, text, &n)) == NULL) {
		*errp = "ctl.conf: its blocks nest too deep";
		return (NULL);
	}
	o = NULL;
	no = 0;
	out = "";
	at = 0;
	for (i = 0; i < n; i++) {
		if (s[i].len != strlen(SECRET_MARK) || memcmp(text + s[i].off,
		    SECRET_MARK, s[i].len) != 0)
			continue;
		if (o == NULL && (was == NULL || (o = ctl_secrets(w, was,
		    &no)) == NULL)) {
			*errp = "ctl.conf: a secret is the marker, and the file "
			    "keeps none: write the secret out";
			return (NULL);
		}
		hit = -1;
		for (k = 0; k < no; k++)
			if (strcmp(o[k].where, s[i].where) == 0) {
				if (hit != -1) {
					*errp = wfmt(w, "ctl.conf: the marker of %s is "
					    "two secrets of the file: write it out",
					    s[i].where);
					return (NULL);
				}
				hit = k;
			}
		if (hit == -1) {
			*errp = wfmt(w, "ctl.conf: the marker of %s has no "
			    "secret in the file: write it out", s[i].where);
			return (NULL);
		}
		out = wfmt(w, "%s%.*s%.*s", out, (int)(s[i].off - at), text + at,
		    (int)o[hit].len, was + o[hit].off);
		at = s[i].off + s[i].len;
	}
	return (wfmt(w, "%s%s", out, text + at));
}

static const char *
tool_out(struct work *w, const char *name, const char *const *args, size_t n)
{
	struct execres	 res;
	const char	*bin;
	char		*argv[8];
	size_t		 i;

	if ((bin = tool(w, name)) == NULL)
		return (NULL);
	argv[0] = (char *)(uintptr_t)bin;
	for (i = 0; i < n && i < 6; i++)
		argv[i + 1] = (char *)(uintptr_t)args[i];
	argv[i + 1] = NULL;
	if (run_exec(w, argv, &res) != 0)
		return (NULL);
	return (wtext(w, res.out));
}

static void
service_json(struct work *w, ucl_object_t *o, const char *name)
{
	bool	enabled, running;

	enabled = running = false;
	service_state(w, name, &running, &enabled);
	put_b(o, wfmt(w, "%s_enabled", name), enabled);
	put_b(o, wfmt(w, "%s_running", name), running);
}

/* nfs_server_flags' words: -n threads, -p the data servers, -m the
 * mirrors. */
static void
nfs_flags_json(struct work *w, ucl_object_t *o, const char *flags)
{
	char	*copy, *it, *word;

	put_s(o, "flags", flags);
	if (flags == NULL)
		return;
	copy = wstrdup(w, flags);
	for (it = copy; (word = strsep(&it, " \t")) != NULL;) {
		if (it == NULL)
			break;
		if (strcmp(word, "-n") == 0)
			put_s(o, "threads", strsep(&it, " \t"));
		else if (strcmp(word, "-p") == 0)
			put_s(o, "pnfs", strsep(&it, " \t"));
		else if (strcmp(word, "-m") == 0)
			put_s(o, "mirror", strsep(&it, " \t"));
	}
}

/*
 * The path of the first V4: line of exports(5), NFSv4's root; NULL
 * for none.  *any says whether the text exports anything at all (a
 * line that is not blank and not a comment).
 */
static const char *
v4_root(struct work *w, const char *text, bool *any)
{
	char	*copy, *it, *line, *p;

	*any = false;
	if (text == NULL)
		return (NULL);
	copy = wstrdup(w, text);
	for (it = copy; (line = strsep(&it, "\n")) != NULL;) {
		line += strspn(line, " \t");
		if (line[0] == '\0' || line[0] == '#')
			continue;
		*any = true;
		if (strncmp(line, "V4:", 3) != 0)
			continue;
		p = line + 3;
		p += strspn(p, " \t");
		p[strcspn(p, " \t\r")] = '\0';
		return (p[0] != '\0' ? p : NULL);
	}
	return (NULL);
}

/*
 * Is the directory on ZFS, the host's or the jail's w works in (opened
 * beneath its root)?  NULL, or why it is not.
 */
static const char *
not_on_zfs(struct work *w, const char *path)
{
	struct statfs	sf;
	int		fd;

	if ((fd = scope_dirfd(w, path)) == -1)
		return (wfmt(w, "%s: %s", path, strerror(errno)));
	if (fstatfs(fd, &sf) == -1) {
		(void)close(fd);
		return (wfmt(w, "%s: %s", path, strerror(errno)));
	}
	(void)close(fd);
	if (strcmp(sf.f_fstypename, "zfs") != 0)
		return (wfmt(w, "%s is not on ZFS (%s)", path, sf.f_fstypename));
	return (NULL);
}

/*
 * Why nfsd(8) may not serve from the jail w works in, as jail(8) has
 * allow.nfsd: it needs a network of its own (vnet), allow.nfsd, and
 * enforce_statfs not 0.  NULL when it may.
 */
static const char *
nfs_jail_unfit(struct work *w)
{
	char	vnet[16], allow[16], statfs_[16];

	if (jail_getv(0, "name", w->jail, "vnet", vnet, "allow.nfsd", allow,
	    "enforce_statfs", statfs_, NULL) < 0)
		return (wfmt(w, "the jail %s: %s: nfsd runs in a jail by "
		    "allow.nfsd (jail(8))", w->jail, jail_errmsg));
	if (strcmp(vnet, "new") != 0 && strcmp(vnet, "1") != 0)
		return (wfmt(w, "the jail %s has no network of its own: nfsd "
		    "serves from a vnet jail alone; set vnet (vnet = new in "
		    "its jail.conf) and give it an interface", w->jail));
	if (strcmp(allow, "1") != 0 && strcmp(allow, "true") != 0)
		return (wfmt(w, "the jail %s may not run nfsd: set allow.nfsd "
		    "(jail(8)) in its jail.conf, or on the running jail", w->jail));
	if (strcmp(statfs_, "0") == 0)
		return (wfmt(w, "the jail %s has enforce_statfs 0: mountd "
		    "exports what the jail sees of its file systems; set "
		    "enforce_statfs to 1, or 2 to export its root's alone",
		    w->jail));
	return (NULL);
}

/*
 * What jail(8) asks of a jail's root for mountd to export from it: a
 * file system's mount point.  NULL, or how it is not.
 */
static const char *
nfs_jail_root(struct work *w)
{
	struct statfs	sf;
	char		real[MAXPATHLEN];

	if (realpath(w->jroot, real) == NULL || statfs(real, &sf) == -1)
		return (wfmt(w, "%s: %s", w->jroot, strerror(errno)));
	if (strcmp(sf.f_mntonname, real) != 0)
		return (wfmt(w, "the jail's root %s is no file system's mount "
		    "point (it is in %s): mountd cannot export from the jail "
		    "until it is (jail(8), allow.nfsd)", real, sf.f_mntonname));
	return (NULL);
}

/* Is a daemon of the jail w works in running, and enabled in its
 * rc.conf by var?  service(8) there by jexec(8), rc.conf by sysrc -j. */
static void
jail_svc_state(struct work *w, const char *name, const char *var,
    bool *running, bool *enabled)
{
	struct execres	 res;
	const char	*v;
	char		*argv[4];

	v = rc_get(w, var);
	*enabled = v != NULL && strcasecmp(v, "yes") == 0;
	argv[0] = (char *)(uintptr_t)opts.service_bin;
	argv[1] = (char *)(uintptr_t)name;
	argv[2] = (char *)(uintptr_t)"onestatus";
	argv[3] = NULL;
	*running = run_exec(w, scope_jexec(w, argv), &res) == 0;
}

/* A daemon of the jail w works in told verb ("one" before it, as its
 * rc.conf may not enable it yet); 0, or -1 with why. */
static int
jail_svc(struct work *w, const char *name, const char *verb,
    const char **errp)
{
	struct execres	 res;
	char		*argv[4];

	argv[0] = (char *)(uintptr_t)opts.service_bin;
	argv[1] = (char *)(uintptr_t)name;
	argv[2] = wfmt(w, "one%s", verb);
	argv[3] = NULL;
	if (run_exec(w, scope_jexec(w, argv), &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, wfmt(w, "service %s one%s "
		    "in %s", name, verb, w->jail)));
		return (-1);
	}
	return (0);
}

/* A ZFS filesystem's name: pool/path, no leading slash, no dots up. */
static bool
dataset_ok(const char *s)
{
	size_t	i, n;

	n = strlen(s);
	if (n == 0 || n > 256 || s[0] == '/' || s[0] == '-' ||
	    strstr(s, "..") != NULL)
		return (false);
	for (i = 0; i < n; i++)
		if (!isalnum((unsigned char)s[i]) && strchr("_.:/-", s[i]) ==
		    NULL)
			return (false);
	return (true);
}

static ucl_object_t *
nfs_json(struct work *w)
{
	ucl_object_t	*o, *arr, *s;
	const char	*v, *root, *why;
	char		*copy, *it, *line, *name, *mnt, *share;
	int		 minor;
	size_t		 len;
	bool		 any;

	o = ucl_object_typed_new(UCL_OBJECT);
	if (w->jail != NULL) {
		bool	enabled, running;

		/* What keeps nfsd from serving there, and what jail(8)
		 * asks of the jail's root. */
		put_s(o, "jail_error", nfs_jail_unfit(w));
		put_s(o, "jail_warning", nfs_jail_root(w));
		jail_svc_state(w, "nfsd", "nfs_server_enable", &running,
		    &enabled);
		put_b(o, "nfsd_enabled", enabled);
		put_b(o, "nfsd_running", running);
		jail_svc_state(w, "mountd", "mountd_enable", &running,
		    &enabled);
		put_b(o, "mountd_enabled", enabled);
		put_b(o, "mountd_running", running);
	} else {
		service_json(w, o, "nfsd");
		service_json(w, o, "mountd");
	}
	put_s(o, "nfs_server_enable", rc_get(w, "nfs_server_enable"));
	put_s(o, "nfsv4_server_enable", rc_get(w, "nfsv4_server_enable"));
	put_s(o, "nfsv4_server_only", rc_get(w, "nfsv4_server_only"));
	put_s(o, "nfsuserd_enable", rc_get(w, "nfsuserd_enable"));
	nfs_flags_json(w, o, rc_get(w, "nfs_server_flags"));
	len = sizeof(minor);
	if (w->jail != NULL) {
		/* The jail's own network's, as sysctl(8) there says. */
		struct execres	 res;
		char		*argv[4];
		const char	*errstr;

		argv[0] = (char *)(uintptr_t)opts.sysctl_bin;
		argv[1] = (char *)(uintptr_t)"-n";
		argv[2] = (char *)(uintptr_t)"vfs.nfsd.server_max_minorversion";
		argv[3] = NULL;
		if (run_exec(w, argv, &res) == 0 && res.out != NULL) {
			minor = (int)strtonum(wstrndup(w, res.out, strcspn(
			    res.out, "\n")), 0, 9, &errstr);
			if (errstr == NULL)
				ucl_object_insert_key(o, ucl_object_fromint(
				    minor), "max_minorversion", 0, false);
		}
	} else if (sysctlbyname("vfs.nfsd.server_max_minorversion", &minor,
	    &len, NULL, 0) == 0)
		ucl_object_insert_key(o, ucl_object_fromint(minor),
		    "max_minorversion", 0, false);
	put_s(o, "exports_path", opts.exports_file);
	if ((v = scope_slurp(w, opts.exports_file, &len)) != NULL) {
		put_s(o, "exports", wtext(w, v));
		/* NFSv4's root, and whether it is on ZFS. */
		if ((root = v4_root(w, v, &any)) != NULL) {
			put_s(o, "v4root", root);
			why = not_on_zfs(w, root);
			ucl_object_insert_key(o, ucl_object_frombool(why == NULL),
			    "v4root_zfs", 0, false);
			if (why != NULL)
				put_s(o, "v4root_error", why);
		}
	}
	/* A jail's mountd exports its exports(5) alone: sharenfs is the
	 * host's. */
	if (w->jail != NULL)
		goto exported;
	/* What zfs wrote for mountd, from the datasets' sharenfs. */
	if ((v = slurp(w, "/etc/zfs/exports")) != NULL)
		put_s(o, "zfs_exports", wtext(w, v));
	/* The datasets that share themselves (sharenfs, zfsprops(7)). */
	{
		struct execres	 res;
		char		*argv[8];

		argv[0] = (char *)(uintptr_t)opts.zfs_bin;
		argv[1] = (char *)(uintptr_t)"list";
		argv[2] = (char *)(uintptr_t)"-H";
		argv[3] = (char *)(uintptr_t)"-o";
		argv[4] = (char *)(uintptr_t)"name,mountpoint,sharenfs";
		argv[5] = (char *)(uintptr_t)"-t";
		argv[6] = (char *)(uintptr_t)"filesystem";
		argv[7] = NULL;
		arr = ucl_object_typed_new(UCL_ARRAY);
		if (run_exec(w, argv, &res) == 0 && res.out != NULL) {
			copy = wstrndup(w, res.out, res.outlen);
			for (it = copy; (line = strsep(&it, "\n")) != NULL;) {
				name = strsep(&line, "\t");
				mnt = strsep(&line, "\t");
				share = line;
				if (name == NULL || mnt == NULL || share == NULL ||
				    strcmp(share, "off") == 0 || strcmp(share, "-") ==
				    0)
					continue;
				s = ucl_object_typed_new(UCL_OBJECT);
				put_s(s, "dataset", name);
				put_s(s, "mountpoint", mnt);
				put_s(s, "sharenfs", share);
				ucl_array_append(arr, s);
			}
		}
		ucl_object_insert_key(o, arr, "shares", 0, false);
	}
exported:
	/* What mountd exports now, as showmount(8) asks it: the jail's
	 * own, there. */
	if (w->jail != NULL) {
		struct execres	 res;
		char		*argv[4];

		argv[0] = (char *)(uintptr_t)"showmount";
		argv[1] = (char *)(uintptr_t)"-e";
		argv[2] = (char *)(uintptr_t)"localhost";
		argv[3] = NULL;
		if (run_exec(w, scope_jexec(w, argv), &res) == 0 && res.out !=
		    NULL)
			put_s(o, "exported", wtext(w, res.out));
	} else {
		static const char *const e[] = { "-e", "localhost" };

		if ((v = tool_out(w, "showmount", e, 2)) != NULL)
			put_s(o, "exported", v);
	}
	return (o);
}

static ucl_object_t *
iscsi_json(struct work *w)
{
	static const char *const devlist[] = { "devlist" };
	static const char *const islist[] = { "islist" };
	static const char *const portlist[] = { "portlist", "-f", "iscsi" };
	ucl_object_t	*o;
	const char	*v;

	o = ucl_object_typed_new(UCL_OBJECT);
	service_json(w, o, "ctld");
	service_json(w, o, "iscsid");
	put_s(o, "conf_path", opts.ctl_conf);
	/* Its CHAP secrets the marker: the read is any role's. */
	if ((v = slurp(w, opts.ctl_conf)) != NULL)
		put_s(o, "conf", wtext(w, ctl_masked(w, v)));
	if ((v = tool_out(w, "ctladm", devlist, 1)) != NULL)
		put_s(o, "luns", v);
	if ((v = tool_out(w, "ctladm", islist, 1)) != NULL)
		put_s(o, "sessions", v);
	if ((v = tool_out(w, "ctladm", portlist, 3)) != NULL)
		put_s(o, "ports", v);
	return (o);
}

static ucl_object_t *
hast_json(struct work *w)
{
	static const char *const status[] = { "status" };
	static const char *const list[] = { "list" };
	ucl_object_t	*o;
	const char	*v;

	o = ucl_object_typed_new(UCL_OBJECT);
	service_json(w, o, "hastd");
	put_s(o, "conf_path", opts.hast_conf);
	if ((v = slurp(w, opts.hast_conf)) != NULL)
		put_s(o, "conf", wtext(w, v));
	if ((v = tool_out(w, "hastctl", status, 1)) != NULL)
		put_s(o, "status", v);
	if ((v = tool_out(w, "hastctl", list, 1)) != NULL)
		put_s(o, "list", v);
	return (o);
}

void
do_netstore(struct work *w, const char *const *names, size_t n,
    struct json_rsp *rsp)
{
	ucl_object_t	*top;
	char		*json;
	size_t		 i;
	bool		 all;

	rsp->has_ok = true;
	rsp->ok = false;
	all = n == 0;
	for (i = 0; i < n; i++)
		if (names[i] == NULL || (strcmp(names[i], "nfs") != 0 &&
		    strcmp(names[i], "iscsi") != 0 && strcmp(names[i], "hast") !=
		    0)) {
			rsp->error = "netstore reads nfs, iscsi and hast, or all "
			    "of them";
			return;
		} else if (w->jail != NULL && strcmp(names[i], "nfs") != 0) {
			rsp->error = wfmt(w, "%s is the host's alone, not a "
			    "jail's: %s", names[i], strcmp(names[i], "iscsi") ==
			    0 ? ISCSI_HOSTS : HAST_HOSTS);
			return;
		}
	top = ucl_object_typed_new(UCL_OBJECT);
	for (i = 0; i < n || (all && i == 0); i++) {
		if (all || strcmp(names[i], "nfs") == 0)
			ucl_object_insert_key(top, nfs_json(w), "nfs", 0, false);
		/* A jail's: its NFS server alone. */
		if (w->jail != NULL)
			continue;
		if (all || strcmp(names[i], "iscsi") == 0)
			ucl_object_insert_key(top, iscsi_json(w), "iscsi", 0,
			    false);
		if (all || strcmp(names[i], "hast") == 0)
			ucl_object_insert_key(top, hast_json(w), "hast", 0,
			    false);
	}
	json = (char *)ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	if (json == NULL) {
		rsp->error = "out of memory";
		return;
	}
	rsp->json = wstrdup(w, json);
	free(json);
	rsp->ok = true;
}

/* ---- Jobs ------------------------------------------------------------ */

static const char *
word(const struct arc_job_spec *sp, const char *key)
{
	size_t	i, k;

	k = strlen(key);
	for (i = 0; i < sp->names.n; i++)
		if (sp->names.v[i] != NULL && strncmp(sp->names.v[i], key, k) ==
		    0 && sp->names.v[i][k] == '=')
			return (sp->names.v[i] + k + 1);
	return (NULL);
}

static bool
yes_no(const char *v)
{

	return (v != NULL && (strcmp(v, "yes") == 0 || strcmp(v, "no") == 0));
}

/* host:/path,host:/path: pNFS's data servers, as nfsd's -p takes them. */
static bool
ds_ok(const char *s)
{
	size_t	n;

	n = strlen(s);
	return (n > 0 && n < 512 && strspn(s, "abcdefghijklmnopqrstuvwxyz"
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_:/,#[]") == n &&
	    strchr(s, ':') != NULL);
}

static bool
words_known(const struct arc_job_spec *sp, const char *const *keys)
{
	const char *const *k;
	size_t		 i, len;

	for (i = 0; i < sp->names.n; i++) {
		if (sp->names.v[i] == NULL)
			return (false);
		for (k = keys; *k != NULL; k++) {
			len = strlen(*k);
			if (strncmp(sp->names.v[i], *k, len) == 0 &&
			    sp->names.v[i][len] == '=')
				break;
		}
		if (*k == NULL)
			return (false);
	}
	return (true);
}

const char *
netstore_check(const struct arc_job_spec *sp)
{
	static const char *const server[] = { "enable", "minor", "threads",
	    "pnfs", "mirror", NULL };
	static const char *const share[] = { "dataset", "sharenfs", NULL };
	static const char *const enable[] = { "enable", NULL };
	static const char *const role[] = { "resource", "role", NULL };
	static const char *const create[] = { "resource", NULL };
	const char	*v;
	bool		 jailed;

	jailed = sp->jail != NULL && sp->jail[0] != '\0';
	if (jailed && sp->kind == ARC_JOB_KIND_ISCSI)
		return ("the iSCSI target is the host's alone: " ISCSI_HOSTS);
	if (jailed && sp->kind == ARC_JOB_KIND_HAST)
		return ("HAST is the host's alone: " HAST_HOSTS);
	if (sp->safe)
		return ("a storage service is not undone: not in safe mode");
	if (sp->verb == NULL)
		return ("a storage job has a verb");
	switch (sp->kind) {
	case ARC_JOB_KIND_NFS:
		if (strcmp(sp->verb, "exports") == 0)
			return (text_ok(sp->text) ? NULL : "exports is the text "
			    "of exports(5)");
		if (strcmp(sp->verb, "share") == 0) {
			if (jailed)
				return ("a dataset's sharenfs is the host's: zfs "
				    "writes the host's /etc/zfs/exports, for the "
				    "host's mountd; a jail exports by its own "
				    "exports(5) (verb exports)");
			if (!words_known(sp, share) || (v = word(sp, "dataset")) ==
			    NULL || !dataset_ok(v))
				return ("share takes dataset= (a ZFS filesystem's "
				    "name) and sharenfs=");
			if ((v = word(sp, "sharenfs")) == NULL || v[0] == '\0' ||
			    strlen(v) > 256 || strcspn(v, "\n\r") != strlen(v))
				return ("sharenfs is on, off or exports(5) options, "
				    "one line");
			return (NULL);
		}
		if (strcmp(sp->verb, "server") != 0)
			return ("an nfs job's verb is exports, share or server");
		if (!words_known(sp, server))
			return ("server takes enable=, minor=, threads=, pnfs= and "
			    "mirror=");
		if ((v = word(sp, "enable")) != NULL && !yes_no(v))
			return ("enable is yes or no");
		if ((v = word(sp, "minor")) != NULL && strcmp(v, "0") != 0 &&
		    strcmp(v, "1") != 0 && strcmp(v, "2") != 0)
			return ("minor is NFSv4's 0, 1 or 2");
		if ((v = word(sp, "threads")) != NULL && (strlen(v) > 3 ||
		    strspn(v, "0123456789") != strlen(v) || atoi(v) < 1 ||
		    atoi(v) > 256))
			return ("threads is 1 to 256");
		/* nfsd(8) in a jail: TCP, and no pNFS. */
		if (jailed && (((v = word(sp, "pnfs")) != NULL && v[0] != '\0') ||
		    ((v = word(sp, "mirror")) != NULL && v[0] != '\0')))
			return ("nfsd in a jail serves without pNFS (nfsd(8)): "
			    "pnfs and mirror are the host's");
		if ((v = word(sp, "pnfs")) != NULL && v[0] != '\0' && !ds_ok(v))
			return ("pnfs is the data servers, host:/path joined by "
			    "commas");
		if ((v = word(sp, "mirror")) != NULL && v[0] != '\0' &&
		    (strspn(v, "0123456789") != strlen(v) || atoi(v) < 2 ||
		    atoi(v) > 8))
			return ("mirror is 2 to 8 (pNFS's mirrors of a file)");
		return (NULL);
	case ARC_JOB_KIND_ISCSI:
		if (strcmp(sp->verb, "conf") == 0)
			return (text_ok(sp->text) ? NULL : "conf is the text of "
			    "ctl.conf(5)");
		if (strcmp(sp->verb, "enable") == 0)
			return (words_known(sp, enable) && yes_no(word(sp,
			    "enable")) ? NULL : "enable takes enable=yes or no");
		return ("an iscsi job's verb is conf or enable");
	case ARC_JOB_KIND_HAST:
		if (strcmp(sp->verb, "conf") == 0)
			return (text_ok(sp->text) ? NULL : "conf is the text of "
			    "hast.conf(5)");
		if (strcmp(sp->verb, "enable") == 0)
			return (words_known(sp, enable) && yes_no(word(sp,
			    "enable")) ? NULL : "enable takes enable=yes or no");
		if (strcmp(sp->verb, "role") == 0 || strcmp(sp->verb,
		    "create") == 0) {
			if (!words_known(sp, strcmp(sp->verb, "role") == 0 ?
			    role : create) || (v = word(sp, "resource")) ==
			    NULL || v[0] == '\0' || strlen(v) > 64 || strspn(v,
			    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
			    "0123456789_-.") != strlen(v) || v[0] == '-' ||
			    v[0] == '.' || strcmp(v, "all") == 0)
				return ("a hast resource is named: resource= "
				    "(one, not all)");
			if (strcmp(sp->verb, "role") == 0 && ((v = word(sp,
			    "role")) == NULL || (strcmp(v, "init") != 0 &&
			    strcmp(v, "primary") != 0 && strcmp(v,
			    "secondary") != 0)))
				return ("role is init, primary or secondary");
			return (NULL);
		}
		return ("a hast job's verb is conf, enable, role or create");
	default:
		return ("not a storage job");
	}
}

char *
netstore_title(const struct arc_job_spec *sp)
{
	const char	*k;
	char		*t;

	k = sp->kind == ARC_JOB_KIND_NFS ? "nfs" : sp->kind ==
	    ARC_JOB_KIND_ISCSI ? "iscsi" : "hast";
	if (asprintf(&t, "%s %s%s%s", k, sp->verb, word(sp, "resource") !=
	    NULL ? " " : "", word(sp, "resource") != NULL ? word(sp,
	    "resource") : "") == -1)
		return (NULL);
	return (t);
}

/*
 * A service enabled or disabled in rc.conf, and started or stopped; a
 * jail's (nfsd alone) in the jail's rc.conf, by its rc.d.
 */
static int
service_onoff(struct work *w, const char *name, bool on, const char **errp)
{
	struct service_action_rsp	 r;

	if (w->jail != NULL)
		return (rc_set(w, "nfs_server_enable", "=", on ? "YES" : "NO",
		    errp) != 0 || jail_svc(w, name, on ? "restart" : "stop",
		    errp) != 0 ? -1 : 0);
	memset(&r, 0, sizeof(r));
	if (do_service_action(w, name, on ? ARC_SERVICE_ACTION_ENABLE :
	    ARC_SERVICE_ACTION_DISABLE, &r) != 0 || !r.ok) {
		*errp = r.error != NULL ? r.error : wfmt(w, "%s not %s", name,
		    on ? "enabled" : "disabled");
		return (-1);
	}
	memset(&r, 0, sizeof(r));
	if (do_service_action(w, name, on ? ARC_SERVICE_ACTION_RESTART :
	    ARC_SERVICE_ACTION_STOP, &r) != 0 || !r.ok) {
		*errp = r.error != NULL ? r.error : wfmt(w, "%s not %s", name,
		    on ? "started" : "stopped");
		return (-1);
	}
	return (0);
}

/* Told to read its configuration again, where it runs; -1 and why
 * when it refuses (the file is written: what it said is the error). */
static int
service_reload(struct work *w, const char *name, const char **errp)
{
	struct service_action_rsp	 r;
	bool				 enabled, running;
	const char			*e;

	enabled = running = false;
	if (w->jail != NULL) {
		/* A jail's mountd, there. */
		jail_svc_state(w, name, "mountd_enable", &running, &enabled);
		e = NULL;
		if (running && jail_svc(w, name, "reload", &e) != 0) {
			*errp = wfmt(w, "written, but %s did not take it: %s",
			    name, e);
			return (-1);
		}
		return (0);
	}
	service_state(w, name, &running, &enabled);
	if (!running)
		return (0);
	memset(&r, 0, sizeof(r));
	if (do_service_action(w, name, ARC_SERVICE_ACTION_RELOAD, &r) != 0 ||
	    !r.ok) {
		*errp = wfmt(w, "written, but %s did not take it: %s", name,
		    r.error != NULL ? r.error : "reload failed");
		return (-1);
	}
	return (0);
}

static int
nfs_server(struct work *w, const struct arc_job_spec *sp, const char **errp)
{
	const char	*v, *flags, *threads, *pnfs, *mirror;
	bool		 on;

	/* NFSv4.2 (or .1, or .0), now and at the next boot. */
	if ((v = word(sp, "minor")) != NULL && do_sysctl_set(w,
	    "vfs.nfsd.server_max_minorversion", v, true, errp) != 0)
		return (-1);
	/* nfsd's flags: its threads, and pNFS's data servers and mirrors
	 * (pnfsserver(4)); the rest as they were. */
	threads = word(sp, "threads");
	pnfs = word(sp, "pnfs");
	mirror = word(sp, "mirror");
	if (threads != NULL || pnfs != NULL || mirror != NULL) {
		/* The flags as they are, -n, -p and -m replaced by what is
		 * given, the others kept. */
		const char	*was = rc_get(w, "nfs_server_flags"), *has_p;
		char		*copy, *it, *tok, out[1024];
		size_t		 off;

		/* Each word put while there is room; past it, refused. */
#define	PUT(...)	do {						\
	if (off < sizeof(out))						\
		off += (size_t)snprintf(out + off, sizeof(out) - off,	\
		    __VA_ARGS__);					\
} while (0)
		/* In a jail TCP alone (nfsd(8)): no -u. */
		copy = wstrdup(w, was != NULL ? was : w->jail != NULL ? "-t -n 4" :
		    "-u -t -n 4");
		out[0] = '\0';
		off = 0;
		has_p = pnfs;
		for (it = copy; (tok = strsep(&it, " \t")) != NULL;) {
			if (tok[0] == '\0' || (w->jail != NULL && strcmp(tok,
			    "-u") == 0))
				continue;
			if ((strcmp(tok, "-n") == 0 && threads != NULL) ||
			    (strcmp(tok, "-p") == 0 && pnfs != NULL) ||
			    (strcmp(tok, "-m") == 0 && (mirror != NULL || (pnfs !=
			    NULL && pnfs[0] == '\0')))) {
				(void)strsep(&it, " \t");
				continue;
			}
			if (strcmp(tok, "-p") == 0 && has_p == NULL)
				has_p = "kept";
			PUT("%s%s", off > 0 ? " " : "", tok);
		}
		if (threads != NULL)
			PUT(" -n %s", threads);
		if (pnfs != NULL && pnfs[0] != '\0')
			PUT(" -p %s", pnfs);
		if (mirror != NULL && mirror[0] != '\0') {
			if (has_p == NULL || has_p[0] == '\0') {
				*errp = "mirror needs pNFS's data servers (pnfs=)";
				return (-1);
			}
			PUT(" -m %s", mirror);
		}
#undef	PUT
		if (off >= sizeof(out)) {
			*errp = "nfsd's flags are too long";
			return (-1);
		}
		flags = out;
		if (rc_set(w, "nfs_server_flags", "=", flags, errp) != 0)
			return (-1);
	}
	if ((v = word(sp, "enable")) != NULL) {
		on = strcmp(v, "yes") == 0;
		/* NFSv4 alone: no NFSv3, so no rpcbind; mountd for the
		 * exports (rc.d/nfsd and rc.d/mountd know the setting). */
		if (on && (rc_set(w, "nfsv4_server_enable", "=", "YES", errp) !=
		    0 || rc_set(w, "nfsv4_server_only", "=", "YES", errp) != 0 ||
		    rc_set(w, "mountd_enable", "=", "YES", errp) != 0))
			return (-1);
		if (service_onoff(w, "nfsd", on, errp) != 0)
			return (-1);
		return (0);
	}
	/* Running: started again, as it reads its flags at its start. */
	{
		bool		 enabled = false, running = false;
		const char	*e;

		if (w->jail != NULL) {
			jail_svc_state(w, "nfsd", "nfs_server_enable", &running,
			    &enabled);
			if (running)
				(void)jail_svc(w, "nfsd", "restart", &e);
			return (0);
		}
		service_state(w, "nfsd", &running, &enabled);
		if (running) {
			struct service_action_rsp	r;

			memset(&r, 0, sizeof(r));
			(void)do_service_action(w, "nfsd",
			    ARC_SERVICE_ACTION_RESTART, &r);
		}
	}
	return (0);
}

/*
 * Why resource name's local provider is the system's own
 * (storage_protected()), each local hast.conf gives it looked at, its
 * own block's and its on blocks' (whichever host this is); NULL when
 * none is, or hast.conf names no such resource.  hastctl create writes
 * HAST's metadata over the provider's end, and a role makes hastd take
 * it.
 */
static const char *
hast_protected(struct work *w, const char *name)
{
	const char	*text, *p, *why;
	char		 tok[MAXPATHLEN], prev[MAXPATHLEN];
	size_t		 n;
	int		 depth, res;
	bool		 named;

	if ((text = slurp(w, opts.hast_conf)) == NULL)
		return (NULL);
	depth = 0;
	res = -1;		/* the depth our resource's block opened at */
	named = false;
	prev[0] = '\0';
	for (p = text; *p != '\0'; ) {
		if (isspace((unsigned char)*p)) {
			p++;
			continue;
		}
		if (*p == '#') {
			p += strcspn(p, "\n");
			continue;
		}
		if (*p == '{' || *p == '}')
			n = 1;
		else
			n = strcspn(p, " \t\r\n{}#");
		(void)snprintf(tok, sizeof(tok), "%.*s", (int)n, p);
		p += n;
		if (strcmp(tok, "{") == 0) {
			if (depth == 0 && named)
				res = 1;
			depth++;
		} else if (strcmp(tok, "}") == 0) {
			if (--depth <= 0) {
				depth = 0;
				res = -1;
			}
			named = false;
		} else if (depth == 0 && strcmp(prev, "resource") == 0)
			named = strcmp(tok, name) == 0;
		else if (res > 0 && strcmp(prev, "local") == 0 &&
		    (why = storage_protected(w, tok, true)) != NULL)
			return (wfmt(w, "its local provider %s: %s", tok, why));
		(void)strlcpy(prev, tok, sizeof(prev));
	}
	return (NULL);
}

/*
 * w in the jail named, when one is, where nfsd may serve (allow.nfsd):
 * refused, saying what to set, where it may not.
 */
static int
nfs_jail_enter(struct work *w, const char *jail, const char **errp)
{
	const char	*why;

	if (scope_enter_jail(w, jail, errp, false) != 0)
		return (-1);
	if (w->jail != NULL && (why = nfs_jail_unfit(w)) != NULL) {
		*errp = why;
		return (-1);
	}
	return (0);
}

int
do_netstore_job(struct work *w, const struct arc_job_spec *sp,
    const char **errp)
{
	static const char *const create[] = { "create", NULL, NULL };
	const char	*v, *bin, *why;
	struct execres	 res;
	char		*argv[6];
	int		 step;

	if ((*errp = netstore_check(sp)) != NULL)
		return (-1);
	switch (sp->kind) {
	case ARC_JOB_KIND_NFS:
		/* A vnet jail's own server, where one is named. */
		if (nfs_jail_enter(w, sp->jail, errp) != 0)
			return (-1);
		if (strcmp(sp->verb, "share") == 0) {
			/* zfs writes /etc/zfs/exports and tells mountd itself. */
			argv[0] = (char *)(uintptr_t)opts.zfs_bin;
			argv[1] = (char *)(uintptr_t)"set";
			argv[2] = wfmt(w, "sharenfs=%s", word(sp, "sharenfs"));
			argv[3] = (char *)(uintptr_t)word(sp, "dataset");
			argv[4] = NULL;
			if (run_exec(w, argv, &res) != 0) {
				*errp = wfmt(w, "zfs set sharenfs: %s", exec_error(w,
				    &res, "zfs set"));
				return (-1);
			}
			return (0);
		}
		if (strcmp(sp->verb, "exports") == 0) {
			const char	*root;
			bool		 any;

			/* NFSv4 alone: nothing is served without the V4:
			 * root, and the root is a directory on ZFS. */
			root = v4_root(w, sp->text, &any);
			if (root == NULL && any) {
				*errp = "NFSv4 alone: exports needs a V4: line, its "
				    "root a directory on ZFS";
				return (-1);
			}
			if (root != NULL && (why = not_on_zfs(w, root)) != NULL) {
				*errp = wfmt(w, "V4: root %s", why);
				return (-1);
			}
			/* A jail's beneath its root, through no link. */
			if (w->jail != NULL) {
				step = step_begin(w, STEP_FILE, "write", "%s's %s",
				    w->jail, opts.exports_file);
				if (scope_replace(w, opts.exports_file, sp->text,
				    strlen(sp->text), 0644, NULL) != 0) {
					*errp = wfmt(w, "%s's %s: %s", w->jail,
					    opts.exports_file, strerror(errno));
					step_end(w, step, false, "%s", *errp);
					return (-1);
				}
				step_end(w, step, true, NULL);
			} else if (put_file(w, opts.exports_file, sp->text, 0644,
			    errp) != 0)
				return (-1);
			/* mountd reads exports(5) again on SIGHUP. */
			return (service_reload(w, "mountd", errp));
		}
		return (nfs_server(w, sp, errp));
	case ARC_JOB_KIND_ISCSI:
		if (strcmp(sp->verb, "conf") == 0) {
			/* The secrets read as the marker kept as they are. */
			if ((v = ctl_unmasked(w, sp->text, slurp(w,
			    opts.ctl_conf), errp)) == NULL || put_file(w,
			    opts.ctl_conf, v, 0600, errp) != 0)
				return (-1);
			return (service_reload(w, "ctld", errp));
		}
		return (service_onoff(w, "ctld", strcmp(word(sp, "enable"),
		    "yes") == 0, errp));
	case ARC_JOB_KIND_HAST:
		if (strcmp(sp->verb, "conf") == 0) {
			if (put_file(w, opts.hast_conf, sp->text, 0644, errp) !=
			    0)
				return (-1);
			return (service_reload(w, "hastd", errp));
		}
		if (strcmp(sp->verb, "enable") == 0)
			return (service_onoff(w, "hastd", strcmp(word(sp,
			    "enable"), "yes") == 0, errp));
		/* The tools' directory's alone when there is one: never
		 * the system's in its place. */
		if ((bin = tool(w, "hastctl")) == NULL) {
			*errp = "the host has no hastctl(8)";
			return (-1);
		}
		v = word(sp, "resource");
		/* Nothing of the system's storage taken by HAST. */
		if ((why = hast_protected(w, v)) != NULL) {
			*errp = wfmt(w, "hast %s %s: %s: it is not touched from "
			    "here", sp->verb, v, why);
			return (-1);
		}
		argv[0] = (char *)(uintptr_t)bin;
		if (strcmp(sp->verb, "role") == 0) {
			argv[1] = (char *)(uintptr_t)"role";
			argv[2] = (char *)(uintptr_t)word(sp, "role");
			argv[3] = (char *)(uintptr_t)v;
			argv[4] = NULL;
		} else {
			argv[1] = (char *)(uintptr_t)create[0];
			argv[2] = (char *)(uintptr_t)v;
			argv[3] = NULL;
		}
		step = step_begin(w, STEP_EXEC, "hastctl", "%s %s",
		    sp->verb, v);
		if (run_exec(w, argv, &res) != 0) {
			*errp = wtext(w, exec_error(w, &res, "hastctl"));
			step_end(w, step, false, "%s", *errp);
			return (-1);
		}
		step_end(w, step, true, NULL);
		return (0);
	default:
		*errp = "not a storage job";
		return (-1);
	}
}
