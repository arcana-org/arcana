/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Console plugins: extensions of the console's page, served by the
 * console.  Not the hosts' plugins (BIRD, Suricata and the others of
 * hosts.c and yplug.c), which run on the hosts.
 *
 * A console plugin is a directory under web.conf's plugins_dir, named
 * by its id, with a plugin.json:
 *
 *	{ "id": "x", "name": "X", "version": "1.0", "arcana": "0.437.0",
 *	  "description": "...", "author": "...",
 *	  "themes": [ { "id": "duo", "name": "Duo", "file": "duo.json" } ],
 *	  "guide-packs": [ { "id": "x", "name": "X",
 *	    "expressions": "expressions.json", "lines": "lines.json" } ],
 *	  "assets": [ "art/a.svg" ], "provides": [ "theme", "guide-pack" ] }
 *
 * arcana is the least console version it runs on; an asset may be a
 * glob(3) pattern, of files of those kinds alone.  Themes and guide
 * packs are data: their JSON is checked here (theme_check(),
 * pack_check()) and the page applies it with its own code.  A plugin
 * with code, "entry" scripts or "styles", says "trusted": true: its
 * script runs as every user who opens the page, with their session.
 * Every file it lists, plugin.json among them, is checked, sized and
 * hashed (SHA-384, the page's integrity); a plugin with anything wrong
 * is listed with why, and none of it is served.  What is served is a
 * listed file of a plugin a console owner enabled, to a signed-in
 * session, from inside the plugin's directory (symbolic links followed
 * only as far as that): what the console host's administrator
 * installed and a console owner enabled alone.
 *
 * The directory is looked at again, at most once a CHECK_MS, on each
 * read of arcana-console's plugins and plugin file asked for: rescanned
 * when it, a plugin's directory, a plugin.json or a directory of a
 * listed file changed; a listed file whose time or size changed hashed
 * again.  Which are
 * enabled is console-plugins.json in the data directory, {"enabled":
 * {"<id>": {"by": who, "at": time}}}, read again when it changed (a
 * cluster's other node wrote it).
 *
 * And a store each, for what a plugin keeps of a user's or of all its
 * users' (api_cplug_store(), below): not for secrets.
 */

#include <sys/param.h>
#include <sys/file.h>
#include <sys/stat.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/evp.h>

#include "console.h"

#define	CPLUG_STATE	"console-plugins.json"
#define	CPLUGS_MAX	64		/* plugins */
#define	CPLUG_FILES	256		/* files a plugin lists */
#define	CPLUG_DIRS	32		/* directories looked at a plugin */
#define	CPLUG_FILE_MAX	(8 * 1024 * 1024)
#define	MANIFEST_MAX	(64 * 1024)
#define	CHECK_MS	1000
#define	ID_MAX		40
#define	PATH_MAX_REL	200
#define	DATA_MAX	16		/* themes, guide packs a plugin has */
#define	DATA_DEPTH	8		/* of a data file's JSON */
#define	DATA_NODES	20000
#define	DATA_TEXT	300		/* bytes of a data file's string */

enum fkind { F_SCRIPT, F_STYLE, F_ASSET };

struct cfile {
	char		*path;		/* in the plugin's directory */
	enum fkind	 kind;
	off_t		 size;
	ino_t		 ino;
	struct timespec	 mtim;
	char		 sri[72];	/* base64 of the SHA-384 */
	bool		 data;		/* a theme's or a guide pack's JSON */
};

struct cwatch {
	char		*path;
	struct timespec	 mtim;
};

struct cplug {
	char		 id[ID_MAX + 1];
	char		*dir;		/* real path, its files' bound */
	ucl_object_t	*m;		/* plugin.json, or NULL */
	char		*error;		/* why it is not served, or NULL */
	struct cfile	*files;
	int		 nfiles;
	struct cwatch	 watch[CPLUG_DIRS];	/* plugin.json the first */
	int		 nwatch;
};

static struct {
	char		*dir;		/* plugins_dir scanned */
	struct timespec	 mtim;
	bool		 scanned;
	uint64_t	 checked;	/* ms, monotonic */
	struct cplug	*v;
	int		 n;
	struct timespec	 state_mtim;	/* of console-plugins.json */
	bool		 state_read;
	ucl_object_t	*state;
} cp;

static const struct {
	const char	*ext;
	const char	*type;
	enum fkind	 kind;
} types[] = {
	{ "js", "text/javascript; charset=utf-8", F_SCRIPT },
	{ "css", "text/css; charset=utf-8", F_STYLE },
	{ "png", "image/png", F_ASSET },
	{ "svg", "image/svg+xml", F_ASSET },
	{ "webp", "image/webp", F_ASSET },
	{ "json", "application/json", F_ASSET },
	{ "woff2", "font/woff2", F_ASSET },
};

/*
 * A theme's design tokens: the custom properties the page's stylesheet
 * (www/arcana-ui/web/style.css) defines on :root that a theme sets, each
 * by what its value is (value_ok()); the page's bridge.js has the same.
 * Nothing else: no url(), no var(), nothing that fetches or runs.
 */
enum tkind { T_COLOUR, T_CHANNELS, T_LENGTH, T_FONT };

static const char *const tkinds[] = {
	[T_COLOUR] = "a colour: #rgb, #rrggbb, rgb(r, g, b) or rgba(r, g, b, a)",
	[T_CHANNELS] = "a colour's channels: r, g, b",
	[T_LENGTH] = "a length: 0, or a number of px, rem or em",
	[T_FONT] = "font names: \"Quoted\" or bare, by commas",
};

static const struct {
	const char	*name;
	enum tkind	 kind;
} tokens[] = {
	{ "--bg", T_COLOUR }, { "--bg-2", T_COLOUR },
	{ "--panel", T_COLOUR }, { "--panel-2", T_COLOUR },
	{ "--line", T_COLOUR }, { "--line-2", T_COLOUR },
	{ "--fg", T_COLOUR }, { "--fg-2", T_COLOUR }, { "--dim", T_COLOUR },
	{ "--cyan", T_COLOUR }, { "--amber", T_COLOUR }, { "--red", T_COLOUR },
	{ "--slate", T_COLOUR }, { "--violet", T_COLOUR },
	{ "--green", T_COLOUR }, { "--blue", T_COLOUR }, { "--teal", T_COLOUR },
	{ "--magenta", T_COLOUR },
	{ "--accent-rgb", T_CHANNELS }, { "--surface-rgb", T_CHANNELS },
	{ "--red-rgb", T_CHANNELS }, { "--amber-rgb", T_CHANNELS },
	{ "--violet-rgb", T_CHANNELS },
	{ "--sans", T_FONT }, { "--mono", T_FONT }, { "--display", T_FONT },
	{ "--cut", T_LENGTH }, { "--radius", T_LENGTH },
};

static uint64_t
now_ms(void)
{
	struct timespec	ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000);
}

static bool
same_time(const struct timespec *a, const struct timespec *b)
{

	return (a->tv_sec == b->tv_sec && a->tv_nsec == b->tv_nsec);
}

/* An id: [a-z0-9-], 1 to 40. */
static bool
id_ok(const char *s)
{
	size_t	n;

	n = strlen(s);
	return (n > 0 && n <= ID_MAX && strspn(s,
	    "abcdefghijklmnopqrstuvwxyz0123456789-") == n);
}

/* What a file's name says it is; -1 for none served. */
static int
type_of(const char *path)
{
	const char	*dot;
	size_t		 i;

	if ((dot = strrchr(path, '.')) == NULL || strchr(dot, '/') != NULL)
		return (-1);
	for (i = 0; i < nitems(types); i++)
		if (strcmp(dot + 1, types[i].ext) == 0)
			return ((int)i);
	return (-1);
}

/*
 * A path in a plugin's directory as plugin.json may name it: relative,
 * no part empty or hidden (".", ".." and dot files with them), of
 * letters, digits and _ . - @ +; with glob, * ? [ ] too.
 */
static bool
path_ok(const char *p, bool glob)
{
	const char	*s;
	size_t		 n;

	n = strlen(p);
	if (n == 0 || n > PATH_MAX_REL || strspn(p, glob ?
	    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	    "0123456789_.-@+/*?[]" :
	    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	    "0123456789_.-@+/") != n)
		return (false);
	/* Each part's first character. */
	for (s = p;; s++) {
		if (*s == '/' || *s == '.' || *s == '\0')
			return (false);
		if ((s = strchr(s, '/')) == NULL)
			return (true);
	}
}

/* "a.b.c" of numbers, into v. */
static bool
version_of(const char *s, long v[3])
{
	char	*e;
	int	 i;

	for (i = 0; i < 3; i++) {
		if (*s < '0' || *s > '9')
			return (false);
		errno = 0;
		v[i] = strtol(s, &e, 10);
		if (errno != 0 || e - s > 6)
			return (false);
		s = e;
		if (i < 2 && *s++ != '.')
			return (false);
	}
	return (*s == '\0');
}

/* Printable text, without controls, at most max bytes. */
static bool
text_ok(const char *s, size_t max)
{
	size_t	n;

	n = strlen(s);
	if (n > max)
		return (false);
	for (; *s != '\0'; s++)
		if ((unsigned char)*s < 0x20 || *s == 0x7f)
			return (false);
	return (true);
}

static void
plug_free(struct cplug *p)
{
	int	i;

	free(p->dir);
	if (p->m != NULL)
		ucl_object_unref(p->m);
	free(p->error);
	for (i = 0; i < p->nfiles; i++)
		free(p->files[i].path);
	free(p->files);
	for (i = 0; i < p->nwatch; i++)
		free(p->watch[i].path);
	memset(p, 0, sizeof(*p));
}

static void
plugs_clear(void)
{
	int	i;

	for (i = 0; i < cp.n; i++)
		plug_free(&cp.v[i]);
	free(cp.v);
	cp.v = NULL;
	cp.n = 0;
}

static bool
fail(struct cplug *p, const char *fmt, ...) __printflike(2, 3);

static bool
fail(struct cplug *p, const char *fmt, ...)
{
	va_list	ap;

	if (p->error != NULL)
		return (false);
	va_start(ap, fmt);
	if (vasprintf(&p->error, fmt, ap) == -1)
		p->error = xstrdup("cannot be read");
	va_end(ap);
	return (false);
}

/*
 * A file of the plugin, read whole into *bufp (when bufp is not NULL)
 * and hashed: its real path inside the plugin's directory, a regular
 * file, not larger than CPLUG_FILE_MAX.  NULL, or why not.
 */
static const char *
file_read(const struct cplug *p, const char *rel, struct stat *sb,
    char sri[72], uint8_t **bufp)
{
	uint8_t		 md[EVP_MAX_MD_SIZE], *buf;
	char		 full[MAXPATHLEN], real[MAXPATHLEN], *b64;
	unsigned int	 mdlen;
	size_t		 dl, got;
	ssize_t		 r;
	int		 fd;

	if (bufp != NULL)
		*bufp = NULL;
	snprintf(full, sizeof(full), "%s/%s", p->dir, rel);
	if (realpath(full, real) == NULL)
		return ("missing");
	dl = strlen(p->dir);
	if (strncmp(real, p->dir, dl) != 0 || real[dl] != '/')
		return ("outside the plugin's directory");
	if ((fd = open(real, O_RDONLY | O_NOFOLLOW | O_CLOEXEC |
	    O_NONBLOCK)) == -1)
		return ("cannot be opened");
	if (fstat(fd, sb) == -1 || !S_ISREG(sb->st_mode)) {
		close(fd);
		return ("not a file");
	}
	if (sb->st_size > CPLUG_FILE_MAX) {
		close(fd);
		return ("larger than 8 MB");
	}
	buf = xmalloc((size_t)sb->st_size + 1);
	for (got = 0; got < (size_t)sb->st_size; got += (size_t)r)
		if ((r = read(fd, buf + got, (size_t)sb->st_size - got)) <= 0)
			break;
	close(fd);
	if (got != (size_t)sb->st_size) {
		free(buf);
		return ("cannot be read");
	}
	EVP_Digest(buf, got, md, &mdlen, EVP_sha384(), NULL);
	b64_encode(md, mdlen, &b64);
	snprintf(sri, 72, "%s", b64);
	free(b64);
	if (bufp != NULL)
		*bufp = buf;
	else
		free(buf);
	return (NULL);
}

/* A directory whose change is looked for. */
static void
watch_add(struct cplug *p, const char *path)
{
	struct stat	sb;
	int		i;

	for (i = 0; i < p->nwatch; i++)
		if (strcmp(p->watch[i].path, path) == 0)
			return;
	if (p->nwatch == CPLUG_DIRS || stat(path, &sb) == -1)
		return;
	p->watch[p->nwatch].path = xstrdup(path);
	p->watch[p->nwatch++].mtim = sb.st_mtim;
}

static struct cfile *
file_find(struct cplug *p, const char *rel)
{
	int	i;

	for (i = 0; i < p->nfiles; i++)
		if (strcmp(p->files[i].path, rel) == 0)
			return (&p->files[i]);
	return (NULL);
}

/* A file listed: checked and hashed once, however often named. */
static bool
file_add(struct cplug *p, const char *rel, enum fkind kind)
{
	struct cfile	*f;
	struct stat	 sb;
	const char	*why;
	char		 dir[MAXPATHLEN], *s;
	int		 t;

	if (file_find(p, rel) != NULL)
		return (true);
	if ((t = type_of(rel)) == -1 || types[t].kind != kind)
		return (fail(p, "%s: %s", rel, kind == F_SCRIPT ? "a script is "
		    "a .js" : kind == F_STYLE ? "a style is a .css" : "an asset "
		    "is a .png, .svg, .webp, .json or .woff2"));
	if (p->nfiles == CPLUG_FILES)
		return (fail(p, "more than %d files", CPLUG_FILES));
	p->files = xrealloc(p->files, sizeof(*p->files) * (size_t)(p->nfiles +
	    1));
	f = &p->files[p->nfiles];
	memset(f, 0, sizeof(*f));
	if ((why = file_read(p, rel, &sb, f->sri, NULL)) != NULL)
		return (fail(p, "%s: %s", rel, why));
	f->path = xstrdup(rel);
	f->kind = kind;
	f->size = sb.st_size;
	f->ino = sb.st_ino;
	f->mtim = sb.st_mtim;
	p->nfiles++;
	snprintf(dir, sizeof(dir), "%s/%s", p->dir, rel);
	if ((s = strrchr(dir, '/')) != NULL) {
		*s = '\0';
		watch_add(p, dir);
	}
	return (true);
}

/* An asset's glob, under the plugin's directory. */
static bool
glob_add(struct cplug *p, const char *pat)
{
	glob_t		 g;
	char		 full[MAXPATHLEN * 2], *o;
	const char	*s, *rel;
	size_t		 i, dl;
	int		 rc;

	/* The directory's own name taken as it is, whatever it holds. */
	for (o = full, s = p->dir; *s != '\0' && o < full + MAXPATHLEN; s++) {
		if (strchr("*?[]\\", *s) != NULL)
			*o++ = '\\';
		*o++ = *s;
	}
	snprintf(o, sizeof(full) - (size_t)(o - full), "/%s", pat);
	memset(&g, 0, sizeof(g));
	if ((rc = glob(full, 0, NULL, &g)) != 0 && rc != GLOB_NOMATCH) {
		globfree(&g);
		return (fail(p, "%s: cannot be looked for", pat));
	}
	dl = strlen(p->dir);
	for (i = 0; i < g.gl_pathc; i++) {
		rel = g.gl_pathv[i] + dl + 1;
		if (!path_ok(rel, false)) {
			globfree(&g);
			return (fail(p, "%s: %s is not a name served", pat, rel));
		}
		if (!file_add(p, rel, F_ASSET)) {
			globfree(&g);
			return (false);
		}
	}
	globfree(&g);
	return (true);
}

/* A list of plugin.json's: of files, or with globs, or of words. */
static bool
list_check(struct cplug *p, const char *key, enum fkind kind, bool words)
{
	const ucl_object_t	*a, *e;
	ucl_object_iter_t	 it;
	const char		*s;

	if ((a = ucl_object_lookup(p->m, key)) == NULL)
		return (true);
	if (ucl_object_type(a) != UCL_ARRAY)
		return (fail(p, "%s is a list", key));
	it = NULL;
	while ((e = ucl_object_iterate(a, &it, true)) != NULL) {
		if (ucl_object_type(e) != UCL_STRING)
			return (fail(p, "%s: a list of strings", key));
		s = ucl_object_tostring(e);
		if (words) {
			if (!id_ok(s) || strlen(s) > 32)
				return (fail(p, "%s: \"%s\" is not a word of "
				    "a-z, 0-9 and -", key, s));
			continue;
		}
		if (!path_ok(s, kind == F_ASSET))
			return (fail(p, "%s: \"%s\" is not a path in the "
			    "plugin's directory", key, s));
		if (kind == F_ASSET && strpbrk(s, "*?[") != NULL) {
			if (!glob_add(p, s))
				return (false);
		} else if (!file_add(p, s, kind))
			return (false);
	}
	return (true);
}

/* A text of plugin.json's: required or not, at most max. */
static bool
text_check(struct cplug *p, const char *key, bool required, size_t max)
{
	const ucl_object_t	*v;

	if ((v = ucl_object_lookup(p->m, key)) == NULL)
		return (required ? fail(p, "%s is missing", key) : true);
	if (ucl_object_type(v) != UCL_STRING || !text_ok(ucl_object_tostring(v),
	    max) || (required && ucl_object_tostring(v)[0] == '\0'))
		return (fail(p, "%s: a line of text, %zu bytes at most", key,
		    max));
	return (true);
}

/* o's keys each one of keys, NULL ended; or why not. */
static bool
keys_only(struct cplug *p, const char *what, const ucl_object_t *o,
    const char *const *keys)
{
	const ucl_object_t	*v;
	ucl_object_iter_t	 it;
	size_t			 i;

	it = NULL;
	while ((v = ucl_object_iterate(o, &it, true)) != NULL) {
		for (i = 0; keys[i] != NULL; i++)
			if (strcmp(ucl_object_key(v), keys[i]) == 0)
				break;
		if (keys[i] == NULL)
			return (fail(p, "%s: unknown key %s", what,
			    ucl_object_key(v)));
	}
	return (true);
}

/* At most max digits at *sp, past them; their value into *v. */
static bool
digits(const char **sp, int max, long *v)
{
	const char	*s;
	int		 n;

	*v = 0;
	for (s = *sp, n = 0; *s >= '0' && *s <= '9'; s++, n++) {
		if (n == max)
			return (false);
		*v = *v * 10 + (*s - '0');
	}
	*sp = s;
	return (n > 0);
}

/* A comma, and the spaces after it, at *sp. */
static bool
comma(const char **sp)
{

	if (**sp != ',')
		return (false);
	for ((*sp)++; **sp == ' '; (*sp)++)
		;
	return (true);
}

/* "r, g, b" at *sp, each 0 to 255; with alpha, ", a" after, 0 to 1. */
static bool
channels(const char **sp, bool alpha)
{
	const char	*s;
	long		 v, f;
	int		 i;

	s = *sp;
	for (i = 0; i < 3; i++)
		if ((i > 0 && !comma(&s)) || !digits(&s, 3, &v) || v > 255)
			return (false);
	if (alpha) {
		if (!comma(&s) || !digits(&s, 1, &v) || v > 1)
			return (false);
		if (*s == '.' && (s++, !digits(&s, 3, &f) || (v == 1 && f != 0)))
			return (false);
	}
	*sp = s;
	return (true);
}

/* A font's family as a theme names it: letters, digits, spaces, -. */
static bool
family_ok(const char *s, size_t n)
{
	size_t	i;

	if (n == 0 || n > 64 || s[0] == ' ')
		return (false);
	for (i = 0; i < n; i++)
		if (strchr("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
		    "0123456789 -", s[i]) == NULL || s[i] == '\0')
			return (false);
	return (true);
}

/* A design token's value of kind k, by a grammar of its own. */
static bool
value_ok(enum tkind k, const char *s)
{
	const char	*e;
	long		 v;
	size_t		 n;
	int		 i;

	if (strlen(s) > 200)
		return (false);
	switch (k) {
	case T_COLOUR:
		if (s[0] == '#') {
			n = strlen(s + 1);
			return ((n == 3 || n == 4 || n == 6 || n == 8) &&
			    strspn(s + 1, "0123456789abcdefABCDEF") == n);
		}
		if (strncmp(s, "rgba(", 5) == 0) {
			s += 5;
			if (!channels(&s, true))
				return (false);
		} else if (strncmp(s, "rgb(", 4) == 0) {
			s += 4;
			if (!channels(&s, false))
				return (false);
		} else
			return (false);
		return (strcmp(s, ")") == 0);
	case T_CHANNELS:
		return (channels(&s, false) && *s == '\0');
	case T_LENGTH:
		if (strcmp(s, "0") == 0)
			return (true);
		if (!digits(&s, 2, &v) || (*s == '.' && (s++,
		    !digits(&s, 2, &v))))
			return (false);
		return (strcmp(s, "px") == 0 || strcmp(s, "rem") == 0 ||
		    strcmp(s, "em") == 0);
	case T_FONT:
		for (i = 0; i < 8; i++) {
			if (*s == '"') {
				if ((e = strchr(s + 1, '"')) == NULL ||
				    !family_ok(s + 1, (size_t)(e - s - 1)))
					return (false);
				s = e + 1;
			} else {
				n = strspn(s, "abcdefghijklmnopqrstuvwxyz"
				    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-");
				if (n == 0 || n > 64 || (*s >= '0' && *s <= '9') ||
				    *s == '-')
					return (false);
				s += n;
			}
			if (*s == '\0')
				return (true);
			if (!comma(&s))
				return (false);
		}
		return (false);
	}
	return (false);
}

/* Whether word is one of the words of list, by spaces. */
static bool
word_in(const char *word, const char *list)
{
	size_t	n;

	n = strlen(word);
	for (;;) {
		if (strncmp(list, word, n) == 0 && (list[n] == ' ' ||
		    list[n] == '\0'))
			return (true);
		if ((list = strchr(list, ' ')) == NULL)
			return (false);
		list++;
	}
}

/*
 * An asset a data file names, relative to that file's directory: a file
 * the plugin lists, of a kind of exts ("svg png webp").
 */
static bool
ref_ok(struct cplug *p, const char *rel, const ucl_object_t *v,
    const char *exts)
{
	struct cfile	*f;
	const char	*s, *ref;
	char		 path[2 * PATH_MAX_REL + 2];
	int		 t;

	if (ucl_object_type(v) != UCL_STRING)
		return (fail(p, "%s: %s: a file's path", rel, ucl_object_key(v)));
	ref = ucl_object_tostring(v);
	s = strrchr(rel, '/');
	snprintf(path, sizeof(path), "%.*s%s", s != NULL ? (int)(s - rel + 1) :
	    0, rel, ref);
	if (!path_ok(ref, false) || !path_ok(path, false) ||
	    (t = type_of(path)) == -1 || !word_in(types[t].ext, exts) ||
	    (f = file_find(p, path)) == NULL || f->kind != F_ASSET)
		return (fail(p, "%s: \"%s\" is not an asset the plugin lists "
		    "(%s)", rel, ref, exts));
	return (true);
}

/*
 * A data file's JSON: every string text of DATA_TEXT bytes at most, its
 * keys of 64, no deeper than DATA_DEPTH nor larger than DATA_NODES; a
 * string of it is text wherever the page shows it, never markup.
 */
static bool
data_walk(struct cplug *p, const char *rel, const ucl_object_t *o,
    int depth, int *nodes)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;

	if (++*nodes > DATA_NODES || depth > DATA_DEPTH)
		return (fail(p, "%s: deeper than %d, or more than %d values",
		    rel, DATA_DEPTH, DATA_NODES));
	switch (ucl_object_type(o)) {
	case UCL_STRING:
		if (!text_ok(ucl_object_tostring(o), DATA_TEXT))
			return (fail(p, "%s: a string is a line of text, %d "
			    "bytes at most", rel, DATA_TEXT));
		break;
	case UCL_OBJECT:
	case UCL_ARRAY:
		it = NULL;
		while ((e = ucl_object_iterate(o, &it, true)) != NULL) {
			if (ucl_object_type(o) == UCL_OBJECT &&
			    !text_ok(ucl_object_key(e), 64))
				return (fail(p, "%s: a key is a word of 64 "
				    "bytes at most", rel));
			if (!data_walk(p, rel, e, depth + 1, nodes))
				return (false);
		}
		break;
	case UCL_INT:
	case UCL_FLOAT:
	case UCL_BOOLEAN:
		break;
	default:
		return (fail(p, "%s: JSON's values alone", rel));
	}
	return (true);
}

/*
 * A data file a plugin.json names under key, listed with the plugin's
 * assets and read: its JSON object, the bytes read the ones listed;
 * NULL, the plugin failed with why.
 */
static ucl_object_t *
data_read(struct cplug *p, const char *key, const ucl_object_t *v)
{
	struct ucl_parser	*ps;
	struct cfile		*f;
	struct stat		 sb;
	ucl_object_t		*o;
	const char		*rel, *why;
	uint8_t			*buf;
	size_t			 i;
	int			 nodes, t;

	rel = ucl_object_tostring(v);
	if (ucl_object_type(v) != UCL_STRING || !path_ok(rel, false) ||
	    (t = type_of(rel)) == -1 || strcmp(types[t].ext, "json") != 0) {
		fail(p, "%s: %s: a .json in the plugin's directory", key,
		    ucl_object_key(v));
		return (NULL);
	}
	if (!file_add(p, rel, F_ASSET))
		return (NULL);
	f = file_find(p, rel);
	f->data = true;
	if ((why = file_read(p, rel, &sb, f->sri, &buf)) != NULL) {
		fail(p, "%s: %s", rel, why);
		return (NULL);
	}
	f->size = sb.st_size;
	f->ino = sb.st_ino;
	f->mtim = sb.st_mtim;
	/* An object as JSON writes one; what else libucl reads is not. */
	for (i = 0; i < (size_t)sb.st_size && strchr(" \t\r\n", buf[i]) !=
	    NULL; i++)
		;
	o = NULL;
	if (i < (size_t)sb.st_size && buf[i] == '{') {
		ps = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
		    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
		if (ucl_parser_add_chunk(ps, buf, (size_t)sb.st_size))
			o = ucl_parser_get_object(ps);
		ucl_parser_free(ps);
	}
	free(buf);
	if (o == NULL || ucl_object_type(o) != UCL_OBJECT) {
		if (o != NULL)
			ucl_object_unref(o);
		fail(p, "%s: not a JSON object", rel);
		return (NULL);
	}
	nodes = 0;
	if (!data_walk(p, rel, o, 0, &nodes)) {
		ucl_object_unref(o);
		return (NULL);
	}
	return (o);
}

/*
 * A theme's file: {"scheme": "dark" or "light", "tokens": {token: value},
 * "font": {"family": name, "file": a .woff2 it lists}}, tokens alone
 * required.
 */
static bool
theme_check(struct cplug *p, const char *rel, const ucl_object_t *o)
{
	static const char *const	 keys[] = { "scheme", "tokens", "font",
					    NULL };
	static const char *const	 fkeys[] = { "family", "file", NULL };
	const ucl_object_t		*v, *e;
	ucl_object_iter_t		 it;
	const char			*s;
	size_t				 i;
	int				 n;

	if (!keys_only(p, rel, o, keys))
		return (false);
	if ((v = ucl_object_lookup(o, "scheme")) != NULL &&
	    (ucl_object_type(v) != UCL_STRING || (strcmp(ucl_object_tostring(v),
	    "dark") != 0 && strcmp(ucl_object_tostring(v), "light") != 0)))
		return (fail(p, "%s: scheme: \"dark\" or \"light\"", rel));
	if ((v = ucl_object_lookup(o, "tokens")) == NULL ||
	    ucl_object_type(v) != UCL_OBJECT)
		return (fail(p, "%s: tokens: an object of the page's design "
		    "tokens", rel));
	it = NULL;
	n = 0;
	while ((e = ucl_object_iterate(v, &it, true)) != NULL) {
		for (i = 0; i < nitems(tokens); i++)
			if (strcmp(ucl_object_key(e), tokens[i].name) == 0)
				break;
		if (i == nitems(tokens))
			return (fail(p, "%s: %s is not one of the page's design "
			    "tokens", rel, ucl_object_key(e)));
		if (ucl_object_type(e) != UCL_STRING ||
		    !value_ok(tokens[i].kind, ucl_object_tostring(e)))
			return (fail(p, "%s: %s: not %s", rel, tokens[i].name,
			    tkinds[tokens[i].kind]));
		n++;
	}
	if (n == 0)
		return (fail(p, "%s: tokens: none", rel));
	if ((v = ucl_object_lookup(o, "font")) == NULL)
		return (true);
	if (ucl_object_type(v) != UCL_OBJECT || !keys_only(p, rel, v, fkeys) ||
	    (s = ucl_str(v, "family")) == NULL ||
	    ucl_object_lookup(v, "file") == NULL)
		return (fail(p, "%s: font: {\"family\": a name, \"file\": a "
		    ".woff2}", rel));
	if (!family_ok(s, strlen(s)))
		return (fail(p, "%s: font: family: letters, digits, spaces and "
		    "-, 64 at most", rel));
	return (ref_ok(p, rel, ucl_object_lookup(v, "file"), "woff2"));
}

/*
 * A guide pack's expressions.json: {"version", "default", "expressions"}
 * and the art, a rig ("rig": an .svg) or a picture an expression
 * ("images": {expression: an .svg, .png or .webp}), files it lists.
 */
static bool
expressions_check(struct cplug *p, const char *rel, const ucl_object_t *o)
{
	static const char *const	 keys[] = { "version", "rig", "images",
					    "default", "expressions", NULL };
	const ucl_object_t		*rig, *img, *v, *e;
	ucl_object_iter_t		 it;
	int				 n;

	if (!keys_only(p, rel, o, keys))
		return (false);
	rig = ucl_object_lookup(o, "rig");
	img = ucl_object_lookup(o, "images");
	if ((rig == NULL) == (img == NULL))
		return (fail(p, "%s: a rig or images, one of them", rel));
	if (rig != NULL && !ref_ok(p, rel, rig, "svg"))
		return (false);
	if (img != NULL) {
		if (ucl_object_type(img) != UCL_OBJECT)
			return (fail(p, "%s: images: {expression: a picture}",
			    rel));
		it = NULL;
		n = 0;
		while ((e = ucl_object_iterate(img, &it, true)) != NULL) {
			if (!id_ok(ucl_object_key(e)))
				return (fail(p, "%s: images: %s is not a word "
				    "of a-z, 0-9 and -", rel, ucl_object_key(e)));
			if (!ref_ok(p, rel, e, "svg png webp"))
				return (false);
			n++;
		}
		if (n == 0)
			return (fail(p, "%s: images: none", rel));
	}
	if ((v = ucl_object_lookup(o, "default")) != NULL &&
	    (ucl_object_type(v) != UCL_STRING || !id_ok(ucl_object_tostring(v))))
		return (fail(p, "%s: default: an expression's name", rel));
	if ((v = ucl_object_lookup(o, "expressions")) == NULL)
		return (true);
	if (ucl_object_type(v) != UCL_OBJECT)
		return (fail(p, "%s: expressions: {name: how the parts stand}",
		    rel));
	it = NULL;
	while ((e = ucl_object_iterate(v, &it, true)) != NULL)
		if (!id_ok(ucl_object_key(e)) || ucl_object_type(e) != UCL_OBJECT)
			return (fail(p, "%s: expressions: %s: a word of a-z, "
			    "0-9 and -, an object", rel, ucl_object_key(e)));
	return (true);
}

/* A guide pack's lines.json: {"version", "placeholders", "moments":
 * {moment: [{"expression", "text"}]}}. */
static bool
lines_check(struct cplug *p, const char *rel, const ucl_object_t *o)
{
	static const char *const	 keys[] = { "version", "placeholders",
					    "moments", NULL };
	static const char *const	 lkeys[] = { "expression", "text",
					    NULL };
	const ucl_object_t		*v, *m, *l, *x;
	ucl_object_iter_t		 it, jt;

	if (!keys_only(p, rel, o, keys))
		return (false);
	if ((v = ucl_object_lookup(o, "moments")) == NULL ||
	    ucl_object_type(v) != UCL_OBJECT)
		return (fail(p, "%s: moments: {moment: [lines]}", rel));
	it = NULL;
	while ((m = ucl_object_iterate(v, &it, true)) != NULL) {
		if (!id_ok(ucl_object_key(m)) || ucl_object_type(m) != UCL_ARRAY)
			return (fail(p, "%s: moments: %s: a word of a-z, 0-9 "
			    "and -, a list", rel, ucl_object_key(m)));
		jt = NULL;
		while ((l = ucl_object_iterate(m, &jt, true)) != NULL) {
			if (ucl_object_type(l) != UCL_OBJECT ||
			    !keys_only(p, rel, l, lkeys) ||
			    (x = ucl_object_lookup(l, "text")) == NULL ||
			    ucl_object_type(x) != UCL_STRING)
				return (fail(p, "%s: moments: %s: each line "
				    "{\"expression\", \"text\"}", rel,
				    ucl_object_key(m)));
			if ((x = ucl_object_lookup(l, "expression")) != NULL &&
			    (ucl_object_type(x) != UCL_STRING ||
			    !id_ok(ucl_object_tostring(x))))
				return (fail(p, "%s: moments: %s: expression: "
				    "an expression's name", rel,
				    ucl_object_key(m)));
		}
	}
	return (true);
}

/*
 * plugin.json's themes and guide packs, each named, its files read and
 * checked:
 *
 *	"themes": [ { "id", "name", "file" } ]
 *	"guide-packs": [ { "id", "name", "expressions", "lines" } ]
 *
 * lines optional.  The ids unique of their kind.
 */
static bool
data_check(struct cplug *p)
{
	static const char *const	 tkeys[] = { "id", "name", "file", NULL };
	static const char *const	 gkeys[] = { "id", "name", "expressions",
					    "lines", NULL };
	static const char *const	 kinds[] = { "themes", "guide-packs" };
	const ucl_object_t		*a, *e, *v;
	ucl_object_iter_t		 it;
	ucl_object_t			*o;
	const char			*id, *name, *seen[DATA_MAX];
	size_t				 k;
	int				 n, j;
	bool				 ok;

	for (k = 0; k < nitems(kinds); k++) {
		if ((a = ucl_object_lookup(p->m, kinds[k])) == NULL)
			continue;
		if (ucl_object_type(a) != UCL_ARRAY || ucl_array_size(a) >
		    DATA_MAX)
			return (fail(p, "%s: a list of %d at most", kinds[k],
			    DATA_MAX));
		it = NULL;
		n = 0;
		while ((e = ucl_object_iterate(a, &it, true)) != NULL) {
			if (ucl_object_type(e) != UCL_OBJECT ||
			    !keys_only(p, kinds[k], e, k == 0 ? tkeys : gkeys))
				return (fail(p, "%s: a list of objects",
				    kinds[k]));
			id = ucl_str(e, "id");
			name = ucl_str(e, "name");
			if (id == NULL || !id_ok(id))
				return (fail(p, "%s: an id of a-z, 0-9 and -, "
				    "%d at most", kinds[k], ID_MAX));
			for (j = 0; j < n; j++)
				if (strcmp(seen[j], id) == 0)
					return (fail(p, "%s: %s twice",
					    kinds[k], id));
			seen[n++] = id;
			if (name == NULL || name[0] == '\0' || !text_ok(name, 64))
				return (fail(p, "%s: %s: name: a line of text, "
				    "64 bytes at most", kinds[k], id));
			if (k == 0) {
				if ((v = ucl_object_lookup(e, "file")) == NULL)
					return (fail(p, "themes: %s: file is "
					    "missing", id));
				if ((o = data_read(p, "themes", v)) == NULL)
					return (false);
				ok = theme_check(p, ucl_object_tostring(v), o);
				ucl_object_unref(o);
				if (!ok)
					return (false);
				continue;
			}
			if ((v = ucl_object_lookup(e, "expressions")) == NULL)
				return (fail(p, "guide-packs: %s: expressions "
				    "is missing", id));
			if ((o = data_read(p, "guide-packs", v)) == NULL)
				return (false);
			ok = expressions_check(p, ucl_object_tostring(v), o);
			ucl_object_unref(o);
			if (!ok)
				return (false);
			if ((v = ucl_object_lookup(e, "lines")) == NULL)
				continue;
			if ((o = data_read(p, "guide-packs", v)) == NULL)
				return (false);
			ok = lines_check(p, ucl_object_tostring(v), o);
			ucl_object_unref(o);
			if (!ok)
				return (false);
		}
	}
	return (true);
}

/*
 * What the plugin is: data alone, themes and guide packs that the page
 * applies itself, or code too (entry, styles), which runs as every user
 * who opens the page and is there only when the plugin says it is
 * trusted.  provides says theme and guide-pack exactly when it has
 * them; a plugin of data alone provides nothing else.
 */
static bool
kind_check(struct cplug *p)
{
	const ucl_object_t	*v, *e;
	ucl_object_iter_t	 it;
	const char		*s;
	bool			 code, trusted, theme, pack, st, sp;
	int			 i;

	if ((v = ucl_object_lookup(p->m, "trusted")) != NULL &&
	    ucl_object_type(v) != UCL_BOOLEAN)
		return (fail(p, "trusted: true or false"));
	trusted = v != NULL && ucl_object_toboolean(v);
	for (code = false, i = 0; i < p->nfiles; i++)
		if (p->files[i].kind != F_ASSET)
			code = true;
	if (code && !trusted)
		return (fail(p, "not trusted: its entry and styles would run as "
		    "every user who opens the page, with their session; a "
		    "plugin with code says \"trusted\": true"));
	if (!code && trusted)
		return (fail(p, "trusted: a plugin of data alone (themes, guide "
		    "packs) has no code to trust"));
	v = ucl_object_lookup(p->m, "themes");
	theme = v != NULL && ucl_array_size(v) > 0;
	v = ucl_object_lookup(p->m, "guide-packs");
	pack = v != NULL && ucl_array_size(v) > 0;
	st = sp = false;
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(p->m, "provides"), &it,
	    true)) != NULL) {
		s = ucl_object_tostring(e);
		if (strcmp(s, "theme") == 0) {
			if (!theme)
				return (fail(p, "provides theme: its themes "
				    "are named in themes"));
			st = true;
		} else if (strcmp(s, "guide-pack") == 0) {
			if (!pack)
				return (fail(p, "provides guide-pack: its "
				    "guide packs are named in guide-packs"));
			sp = true;
		} else if (!code)
			return (fail(p, "provides %s: a plugin of data alone "
			    "provides theme and guide-pack", s));
	}
	if (theme && !st)
		return (fail(p, "themes: provides says theme"));
	if (pack && !sp)
		return (fail(p, "guide-packs: provides says guide-pack"));
	return (true);
}

/* plugin.json read and checked, and the files it lists. */
static void
plug_load(struct cplug *p, const char *top, const char *name)
{
	static const char	*keys[] = { "id", "name", "version", "arcana",
				    "description", "author", "trusted", "entry",
				    "styles", "assets", "themes", "guide-packs",
				    "provides" };
	struct ucl_parser	*ps;
	const ucl_object_t	*v;
	ucl_object_iter_t	 it;
	struct stat		 sb;
	char			 path[MAXPATHLEN], real[MAXPATHLEN];
	const char		*s;
	long			 want[3], have[3];
	size_t			 i;
	int			 fd;

	snprintf(p->id, sizeof(p->id), "%s", name);
	if (!id_ok(name)) {
		fail(p, "the directory's name is not an id: a-z, 0-9 and -, "
		    "%d at most", ID_MAX);
		return;
	}
	snprintf(path, sizeof(path), "%s/%s", top, name);
	if (realpath(path, real) == NULL) {
		fail(p, "cannot be read");
		return;
	}
	p->dir = xstrdup(real);
	snprintf(path, sizeof(path), "%s/plugin.json", p->dir);
	watch_add(p, path);
	watch_add(p, p->dir);
	if (p->nwatch != 2) {
		fail(p, "no plugin.json");
		return;
	}
	if ((fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)) == -1 ||
	    fstat(fd, &sb) == -1 || !S_ISREG(sb.st_mode) ||
	    sb.st_size > MANIFEST_MAX) {
		if (fd != -1)
			close(fd);
		fail(p, "plugin.json is not a file of %d KB at most",
		    MANIFEST_MAX / 1024);
		return;
	}
	/* No macros: nothing included from elsewhere. */
	ps = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	if (!ucl_parser_add_fd(ps, fd)) {
		fail(p, "plugin.json: %s", ucl_parser_get_error(ps));
		ucl_parser_free(ps);
		close(fd);
		return;
	}
	close(fd);
	p->m = ucl_parser_get_object(ps);
	ucl_parser_free(ps);
	if (p->m == NULL || ucl_object_type(p->m) != UCL_OBJECT) {
		fail(p, "plugin.json is not an object");
		return;
	}
	/* What it needs first: a newer console's plugin may say more. */
	if (!text_check(p, "arcana", true, 20))
		return;
	s = ucl_str(p->m, "arcana");
	if (!version_of(s, want)) {
		fail(p, "arcana: the least console version, as 0.337.0");
		return;
	}
	if (!version_of(ARCW_VERSION, have)) {
		fail(p, "this console's version %s is not a.b.c",
		    ARCW_VERSION);
		return;
	}
	for (i = 0; i < 3 && want[i] == have[i]; i++)
		;
	if (i < 3 && want[i] > have[i]) {
		fail(p, "needs console %s or newer; this is %s", s,
		    ARCW_VERSION);
		return;
	}
	it = NULL;
	while ((v = ucl_object_iterate(p->m, &it, true)) != NULL) {
		for (i = 0; i < nitems(keys); i++)
			if (strcmp(ucl_object_key(v), keys[i]) == 0)
				break;
		if (i == nitems(keys)) {
			fail(p, "plugin.json: unknown key %s",
			    ucl_object_key(v));
			return;
		}
	}
	if (!text_check(p, "id", true, ID_MAX))
		return;
	if (strcmp(ucl_str(p->m, "id"), name) != 0) {
		fail(p, "id %s is not the directory's name", ucl_str(p->m,
		    "id"));
		return;
	}
	if (!text_check(p, "name", true, 64) ||
	    !text_check(p, "version", true, 32) ||
	    !text_check(p, "description", false, 1024) ||
	    !text_check(p, "author", false, 128))
		return;
	s = ucl_str(p->m, "version");
	if (strspn(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	    "0123456789.+-") != strlen(s)) {
		fail(p, "version: letters, digits and . + -");
		return;
	}
	/* Itself last: the page reads its themes and guide packs in it. */
	(void)(list_check(p, "provides", F_ASSET, true) &&
	    list_check(p, "entry", F_SCRIPT, false) &&
	    list_check(p, "styles", F_STYLE, false) &&
	    list_check(p, "assets", F_ASSET, false) && data_check(p) &&
	    kind_check(p) && file_add(p, "plugin.json", F_ASSET));
}

static int
plug_cmp(const void *a, const void *b)
{

	return (strcmp(((const struct cplug *)a)->id,
	    ((const struct cplug *)b)->id));
}

/* plugins_dir read again whole. */
static void
rescan(const char *top, const struct stat *tsb)
{
	DIR		*d;
	struct dirent	*e;
	struct stat	 sb;
	char		 path[MAXPATHLEN];

	plugs_clear();
	cp.mtim = tsb->st_mtim;
	if ((d = opendir(top)) == NULL)
		return;
	while ((e = readdir(d)) != NULL) {
		if (e->d_name[0] == '.')
			continue;
		/* A directory of its own; not a link to one elsewhere. */
		snprintf(path, sizeof(path), "%s/%s", top, e->d_name);
		if (lstat(path, &sb) == -1 || !S_ISDIR(sb.st_mode))
			continue;
		if (cp.n == CPLUGS_MAX) {
			log_msg(LOG_WARNING, "%s: more than %d console plugins, "
			    "the rest not read", top, CPLUGS_MAX);
			break;
		}
		cp.v = xrealloc(cp.v, sizeof(*cp.v) * (size_t)(cp.n + 1));
		memset(&cp.v[cp.n], 0, sizeof(cp.v[cp.n]));
		plug_load(&cp.v[cp.n], top, e->d_name);
		if (cp.v[cp.n].error != NULL)
			log_msg(LOG_WARNING, "console plugin %s: %s",
			    cp.v[cp.n].id, cp.v[cp.n].error);
		cp.n++;
	}
	closedir(d);
	qsort(cp.v, (size_t)cp.n, sizeof(*cp.v), plug_cmp);
}

/* A listed file changed since: hashed again; false when it is gone, no
 * longer what may be served, or data to be checked again. */
static bool
file_fresh(struct cplug *p, struct cfile *f)
{
	struct stat	 sb;
	char		 full[MAXPATHLEN];

	snprintf(full, sizeof(full), "%s/%s", p->dir, f->path);
	if (stat(full, &sb) == -1)
		return (false);
	if (sb.st_size == f->size && sb.st_ino == f->ino &&
	    same_time(&sb.st_mtim, &f->mtim))
		return (true);
	if (f->data || file_read(p, f->path, &sb, f->sri, NULL) != NULL)
		return (false);
	f->size = sb.st_size;
	f->ino = sb.st_ino;
	f->mtim = sb.st_mtim;
	return (true);
}

/* The directory looked at, at most once a CHECK_MS. */
static void
cplug_check(void)
{
	struct stat	 sb;
	const char	*top;
	uint64_t	 now;
	bool		 again;
	int		 i, j;

	now = now_ms();
	if (cp.scanned && now - cp.checked < CHECK_MS)
		return;
	cp.checked = now;
	top = cfg.plugins_dir;
	if (top == NULL || top[0] == '\0' || stat(top, &sb) == -1 ||
	    !S_ISDIR(sb.st_mode)) {
		plugs_clear();
		cp.scanned = true;
		free(cp.dir);
		cp.dir = NULL;
		return;
	}
	again = !cp.scanned || cp.dir == NULL || strcmp(cp.dir, top) != 0 ||
	    !same_time(&sb.st_mtim, &cp.mtim);
	for (i = 0; !again && i < cp.n; i++) {
		struct cplug	*p = &cp.v[i];
		struct stat	 wsb;

		for (j = 0; !again && j < p->nwatch; j++)
			again = stat(p->watch[j].path, &wsb) == -1 ||
			    !same_time(&wsb.st_mtim, &p->watch[j].mtim);
		for (j = 0; !again && p->error == NULL && j < p->nfiles; j++)
			again = !file_fresh(p, &p->files[j]);
	}
	if (again) {
		free(cp.dir);
		cp.dir = xstrdup(top);
		rescan(top, &sb);
	}
	cp.scanned = true;
}

/* console-plugins.json, read again when it changed. */
static void
state_check(void)
{
	struct stat	sb;
	char		path[MAXPATHLEN];

	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, CPLUG_STATE);
	if (stat(path, &sb) == -1)
		memset(&sb, 0, sizeof(sb));
	if (cp.state_read && same_time(&sb.st_mtim, &cp.state_mtim))
		return;
	if (cp.state != NULL)
		ucl_object_unref(cp.state);
	if ((cp.state = store_load(CPLUG_STATE)) == NULL ||
	    ucl_object_type(cp.state) != UCL_OBJECT) {
		if (cp.state != NULL)
			ucl_object_unref(cp.state);
		cp.state = ucl_object_typed_new(UCL_OBJECT);
	}
	if (ucl_object_lookup(cp.state, "enabled") == NULL)
		ucl_object_insert_key(cp.state, ucl_object_typed_new(UCL_OBJECT),
		    "enabled", 0, false);
	cp.state_mtim = sb.st_mtim;
	cp.state_read = true;
}

static bool
enabled(const char *id)
{

	return (ucl_object_lookup(ucl_object_lookup(cp.state, "enabled"), id)
	    != NULL);
}

static struct cplug *
plug_find(const char *id)
{
	int	i;

	for (i = 0; i < cp.n; i++)
		if (strcmp(cp.v[i].id, id) == 0)
			return (&cp.v[i]);
	return (NULL);
}

static void
put(ucl_object_t *o, const char *key, ucl_object_t *v)
{

	ucl_object_insert_key(o, v, key, 0, true);
}

static int	plug_set(const char *, bool, const char *, char *, size_t);

/* The plugin's id of arcana-console's plugins/plugin=<id>/... */
static bool
plug_id_of(struct http_request *req, char *id, size_t len)
{
	static const char	pre[] = CYANG_DATA "plugins/plugin=";
	const char		*p;
	size_t			 n;

	if (strncmp(req->path, pre, sizeof(pre) - 1) != 0)
		return (false);
	p = req->path + sizeof(pre) - 1;
	if ((n = strcspn(p, "/")) == 0 || n >= len)
		return (false);
	memcpy(id, p, n);
	id[n] = '\0';
	return (id_ok(id));
}

/* Plugin id enabled or not by who: 0, or the HTTP status and why. */
static int
plug_set(const char *id, bool on, const char *who, char *why, size_t len)
{
	ucl_object_t	*st, *e, *rec;
	struct stat	 sb;
	struct cplug	*p;
	char		 path[MAXPATHLEN];

	p = plug_find(id);
	if (on && p == NULL) {
		snprintf(why, len, "no plugin %s in %s", id, cfg.plugins_dir !=
		    NULL ? cfg.plugins_dir : "(none)");
		return (404);
	}
	if (on && p->error != NULL) {
		snprintf(why, len, "plugin %s: %s", id, p->error);
		return (409);
	}
	if (on == enabled(id))
		return (0);
	st = ucl_object_copy(cp.state);
	e = (ucl_object_t *)(uintptr_t)ucl_object_lookup(st, "enabled");
	if (on) {
		rec = ucl_object_typed_new(UCL_OBJECT);
		put(rec, "by", ucl_object_fromstring(who));
		put(rec, "at", ucl_object_fromint(time(NULL)));
		put(e, id, rec);
	} else
		ucl_object_delete_key(e, id);
	if (store_save(CPLUG_STATE, st) != 0) {
		ucl_object_unref(st);
		snprintf(why, len, "%s could not be written", CPLUG_STATE);
		return (500);
	}
	/* In force at once; a cluster's write, when it comes, the same
	 * read again. */
	ucl_object_unref(cp.state);
	cp.state = st;
	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, CPLUG_STATE);
	if (stat(path, &sb) == 0)
		cp.state_mtim = sb.st_mtim;
	audit_add(on ? "plugin-enabled" : "plugin-disabled", "Administer",
	    id, CPLUG_STATE, "the console", who, "plugin %s %s", id, on ?
	    "enabled" : "disabled");
	log_msg(LOG_NOTICE, "console plugin %s %s by %s", id, on ?
	    "enabled" : "disabled", who);
	cyang_changed("plugins");
	return (0);
}

/* arcana-console's plugins (cyang.c): the list, typed. */
ucl_object_t *
cplugs_yang(struct http_request *req)
{
	static const char	*texts[] = { "name", "version", "arcana",
				    "description", "author" };
	const ucl_object_t	*v;
	ucl_object_t		*top, *list, *o, *f, *a;
	size_t			 i;
	int			 k, j;

	cplug_check();
	state_check();
	list = ucl_object_typed_new(UCL_ARRAY);
	for (k = 0; k < cp.n; k++) {
		o = ucl_object_typed_new(UCL_OBJECT);
		put(o, "id", ucl_object_fromstring(cp.v[k].id));
		put(o, "enabled", ucl_object_frombool(enabled(cp.v[k].id)));
		for (i = 0; i < nitems(texts); i++)
			if (cp.v[k].m != NULL && (v = ucl_object_lookup(
			    cp.v[k].m, texts[i])) != NULL &&
			    ucl_object_type(v) == UCL_STRING)
				put(o, texts[i], ucl_object_copy(v));
		if (cp.v[k].error != NULL) {
			put(o, "error", ucl_object_fromstring(cp.v[k].error));
			ucl_array_append(list, o);
			continue;
		}
		if (cp.v[k].m != NULL && (v = ucl_object_lookup(cp.v[k].m,
		    "provides")) != NULL && ucl_object_type(v) == UCL_ARRAY &&
		    ucl_array_size(v) > 0)
			put(o, "provides", ucl_object_copy(v));
		a = ucl_object_typed_new(UCL_ARRAY);
		for (j = 0; j < cp.v[k].nfiles; j++) {
			char	sri[80];

			f = ucl_object_typed_new(UCL_OBJECT);
			put(f, "path", ucl_object_fromstring(
			    cp.v[k].files[j].path));
			put(f, "kind", ucl_object_fromstring(
			    cp.v[k].files[j].kind == F_SCRIPT ? "script" :
			    cp.v[k].files[j].kind == F_STYLE ? "style" :
			    "asset"));
			put(f, "size", ucl_object_fromint(
			    cp.v[k].files[j].size));
			snprintf(sri, sizeof(sri), "sha384-%s",
			    cp.v[k].files[j].sri);
			put(f, "integrity", ucl_object_fromstring(sri));
			ucl_array_append(a, f);
		}
		put(o, "file", a);
		ucl_array_append(list, o);
	}
	top = ucl_object_typed_new(UCL_OBJECT);
	if (user_console(session_user(req)) == CROLE_OWNER)
		put(top, "directory", ucl_object_fromstring(cfg.plugins_dir !=
		    NULL ? cfg.plugins_dir : ""));
	put(top, "plugin", list);
	return (top);
}

/*
 * The plugins' change from was to now: each enabled or not, by an owner
 * of the console alone (plug_set()); a plugin is installed and removed
 * in its directory, not here.  0, or the HTTP status and why.
 */
int
cplugs_yang_set(struct http_request *req, const ucl_object_t *was,
    const ucl_object_t *now, char *why, size_t len)
{
	const ucl_object_t	*wl, *nl, *e, *o;
	ucl_object_iter_t	 it;
	const char		*id, *who;
	int			 st;

	wl = ucl_object_lookup(was, "plugin");
	nl = ucl_object_lookup(now, "plugin");
	if (ucl_array_size(wl) != ucl_array_size(nl)) {
		snprintf(why, len, "a plugin is installed and removed in %s",
		    cfg.plugins_dir != NULL ? cfg.plugins_dir : "the plugins "
		    "directory");
		return (400);
	}
	it = NULL;
	while ((e = ucl_object_iterate(nl, &it, true)) != NULL) {
		id = ucl_str(e, "id");
		if ((o = cyang_entry(wl, "id", id)) == NULL) {
			snprintf(why, len, "no plugin %s in %s", id,
			    cfg.plugins_dir != NULL ? cfg.plugins_dir :
			    "(none)");
			return (404);
		}
		if (ucl_object_toboolean(ucl_object_lookup(o, "enabled")) ==
		    ucl_object_toboolean(ucl_object_lookup(e, "enabled")))
			continue;
		if (user_console(session_user(req)) != CROLE_OWNER) {
			snprintf(why, len, "a console plugin is enabled or "
			    "disabled by an owner of this console alone");
			return (403);
		}
		if (ucl_object_toboolean(ucl_object_lookup(e, "enabled")) &&
		    plug_find(id) != NULL && plug_find(id)->error != NULL) {
			snprintf(why, len, "plugin %s: %s", id,
			    plug_find(id)->error);
			return (409);
		}
	}
	who = session_who(req) != NULL ? session_who(req) : "?";
	it = NULL;
	while ((e = ucl_object_iterate(nl, &it, true)) != NULL)
		if ((st = plug_set(ucl_str(e, "id"), ucl_object_toboolean(
		    ucl_object_lookup(e, "enabled")), who, why, len)) != 0)
			return (st);
	return (0);
}

/* A 404 of the plugin files' own: plain, as the web root's. */
static int
not_found(struct http_request *req)
{

	http_response_header(req, "content-type", "text/plain; charset=utf-8");
	http_response(req, 404, "Not Found\n", 10);
	return (WEB_OK);
}

/*
 * GET /plugins/<id>/<file>: a file a plugin lists, the plugin enabled,
 * to a signed-in session; anything else not found.  Its tag the hash,
 * looked at each time.
 */
int
api_cplug_file(struct http_request *req)
{
	struct cplug	*p;
	struct stat	 sb;
	const char	*rel, *why, *v;
	uint8_t		*buf;
	char		 id[ID_MAX + 1], sri[72], etag[96];
	int		 i, t;

	if (!guard(req, false))
		return (WEB_OK);
	if (!capture(req, 2, id, sizeof(id)) || !id_ok(id))
		return (not_found(req));
	rel = req->path + strlen("/plugins/") + strlen(id) + 1;
	if (!path_ok(rel, false))
		return (not_found(req));
	cplug_check();
	state_check();
	if ((p = plug_find(id)) == NULL || p->error != NULL || !enabled(id))
		return (not_found(req));
	for (i = 0; i < p->nfiles; i++)
		if (strcmp(p->files[i].path, rel) == 0)
			break;
	if (i == p->nfiles || (t = type_of(rel)) == -1)
		return (not_found(req));
	/* Read and hashed as it is now: what is sent is what is tagged. */
	if ((why = file_read(p, rel, &sb, sri, &buf)) != NULL) {
		log_msg(LOG_WARNING, "console plugin %s: %s: %s", id, rel, why);
		cp.scanned = false;
		return (not_found(req));
	}
	/* Data not as it was checked: not served until checked again. */
	if (strcmp(sri, p->files[i].sri) != 0 && p->files[i].data) {
		free(buf);
		cp.scanned = false;
		return (not_found(req));
	}
	if (strcmp(sri, p->files[i].sri) != 0) {
		snprintf(p->files[i].sri, sizeof(p->files[i].sri), "%s", sri);
		p->files[i].size = sb.st_size;
		p->files[i].ino = sb.st_ino;
		p->files[i].mtim = sb.st_mtim;
	}
	snprintf(etag, sizeof(etag), "\"sha384-%s\"", sri);
	http_response_header(req, "cache-control", "no-cache");
	http_response_header(req, "etag", etag);
	if (http_request_header(req, "if-none-match", &v) &&
	    strcmp(v, etag) == 0) {
		free(buf);
		http_response(req, 304, NULL, 0);
		return (WEB_OK);
	}
	http_response_header(req, "content-type", types[t].type);
	/*
	 * A picture is for an <img>: as a document of its own (the address
	 * opened) an SVG runs nothing, fetches nothing and is saved, not
	 * shown, whatever it holds.
	 */
	if (strcmp(types[t].ext, "svg") == 0) {
		http_response_header(req, "content-security-policy",
		    "default-src 'none'; style-src 'unsafe-inline'; "
		    "img-src data:; sandbox");
		http_response_header(req, "content-disposition", "attachment");
	}
	http_response(req, 200, buf, (size_t)sb.st_size);
	free(buf);
	return (WEB_OK);
}

/*
 * A plugin's store: a JSON object of 16 KB at most for each console user
 * and one its users share, in plugin-store/ of the data directory,
 *
 *	<plugin>.shared.json
 *	<plugin>.user.<user>.json
 *
 * the user's name with its '_', '.' and '@' written _5f, _2e and _40:
 * a name the cluster replicates (store_save()), which no user's can be
 * mistaken for the shared one's.  Written under a lock every worker
 * and the cluster's nodes take, each tagged by the SHA-256 of its
 * compact JSON: a write names the tag it replaces (If-Match), or finds
 * none stored.  Kept while the plugin is disabled; a user's go with the
 * user.
 */
#define	PSTORE_DIR	"plugin-store"
#define	PSTORE_LOCK	"plugin-store.lock"
#define	PSTORE_MAX	(16 * 1024)
#define	PSTORE_USER	(3 * 64 + 1)

/* user's name as its file has it; false when it does not fit. */
static bool
pstore_user(const char *user, char *buf, size_t len)
{
	size_t	i, n;

	for (i = n = 0; user[i] != '\0'; i++) {
		if (n + 4 > len)
			return (false);
		if (user[i] == '_' || user[i] == '.' || user[i] == '@')
			n += (size_t)snprintf(buf + n, len - n, "_%02x",
			    (unsigned char)user[i]);
		else
			buf[n++] = user[i];
	}
	buf[n] = '\0';
	return (n > 0);
}

/* The store of plugin id: user's, or with user NULL the shared one. */
static bool
pstore_name(const char *id, const char *user, char *buf, size_t len)
{
	char	u[PSTORE_USER];

	if (user == NULL) {
		snprintf(buf, len, "%s/%s.shared.json", PSTORE_DIR, id);
		return (true);
	}
	if (!pstore_user(user, u, sizeof(u)))
		return (false);
	snprintf(buf, len, "%s/%s.user.%s.json", PSTORE_DIR, id, u);
	return (true);
}

/* o's tag, "<32 hex>" quoted, into etag; its compact JSON's length, or
 * -1. */
static ssize_t
pstore_tag(const ucl_object_t *o, char etag[36])
{
	unsigned char	 md[EVP_MAX_MD_SIZE];
	unsigned int	 mdlen;
	char		*js;
	size_t		 len;
	int		 i;

	if ((js = (char *)ucl_object_emit(o, UCL_EMIT_JSON_COMPACT)) == NULL)
		return (-1);
	len = strlen(js);
	if (EVP_Digest(js, len, md, &mdlen, EVP_sha256(), NULL) != 1) {
		free(js);
		return (-1);
	}
	free(js);
	etag[0] = '"';
	for (i = 0; i < 16; i++)
		snprintf(etag + 1 + 2 * i, 3, "%02x", md[i]);
	etag[33] = '"';
	etag[34] = '\0';
	return ((ssize_t)len);
}

/* What name holds, and its tag; or NULL and "". */
static ucl_object_t *
pstore_load(const char *name, char etag[36])
{
	ucl_object_t	*o;

	etag[0] = '\0';
	if ((o = store_load(name)) == NULL)
		return (NULL);
	if (ucl_object_type(o) != UCL_OBJECT || pstore_tag(o, etag) == -1) {
		ucl_object_unref(o);
		etag[0] = '\0';
		return (NULL);
	}
	return (o);
}

static int
pstore_lock(void)
{
	char	path[MAXPATHLEN];
	int	fd;

	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, PSTORE_LOCK);
	if ((fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600)) == -1)
		return (-1);
	(void)flock(fd, LOCK_EX);
	/* And of the cluster's other nodes, when it is one. */
	(void)cluster_lock(PSTORE_LOCK);
	return (fd);
}

static void
pstore_unlock(int fd)
{

	if (fd != -1) {
		cluster_unlock(PSTORE_LOCK);
		close(fd);
	}
}

/* The body, a JSON object of PSTORE_MAX bytes at most, into *op: 0, else
 * 413 or 400. */
static int
pstore_body(struct http_request *req, ucl_object_t **op)
{
	struct ucl_parser	*p;
	char			*buf;
	size_t			 len, i;
	ssize_t			 r;
	int			 status;

	*op = NULL;
	buf = xmalloc(PSTORE_MAX + 1);
	for (len = 0; len < PSTORE_MAX + 1; len += (size_t)r)
		if ((r = http_body_read(req, buf + len, PSTORE_MAX + 1 - len)) <=
		    0)
			break;
	if (len > PSTORE_MAX) {
		free(buf);
		return (413);
	}
	/* An object as JSON writes one; what else libucl reads is not. */
	for (i = 0; i < len && strchr(" \t\r\n", buf[i]) != NULL; i++)
		;
	status = 400;
	if (i < len && buf[i] == '{') {
		p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
		    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
		if (ucl_parser_add_chunk(p, (unsigned char *)buf, len) &&
		    (*op = ucl_parser_get_object(p)) != NULL) {
			if (ucl_object_type(*op) == UCL_OBJECT)
				status = 0;
			else {
				ucl_object_unref(*op);
				*op = NULL;
			}
		}
		ucl_parser_free(p);
	}
	free(buf);
	return (status);
}

/*
 * GET arcana-console's plugins/plugin=<id>/store or shared-store: the
 * object, its tag the ETag; none, 404.  PUT: the object, in place of
 * the one If-Match names (*: any one), or without If-Match where none
 * is stored yet; its tag the ETag.  The session user's own, or the one
 * shared, which any console role reads and an operator or an owner
 * writes.  Not an API token's; the plugin enabled and served, else not
 * found.
 */
int
api_cplug_store(struct http_request *req)
{
	ucl_object_t	*o, *cur, *top;
	const char	*user, *v;
	char		 id[ID_MAX + 1], name[MAXPATHLEN], etag[36], now[36];
	struct cplug	*p;
	ssize_t		 len;
	size_t		 plen;
	bool		 shared, ok;
	int		 fd, status;

	plen = strlen(req->path);
	shared = plen > 13 && strcmp(req->path + plen - 13, "/shared-store") ==
	    0;
	if (!guard(req, req->method != HTTP_METHOD_GET))
		return (WEB_OK);
	if ((user = session_user(req)) == NULL)
		return (reply_error(req, 403, "token", "a plugin's store is a "
		    "console user's, not an API token's"));
	if (!plug_id_of(req, id, sizeof(id)))
		return (reply_error(req, 404, "not_found", "no such plugin"));
	cplug_check();
	state_check();
	if ((p = plug_find(id)) == NULL || p->error != NULL || !enabled(id))
		return (reply_error(req, 404, "not_found", "no plugin %s "
		    "enabled", id));
	if (!pstore_name(id, shared ? NULL : user, name, sizeof(name)))
		return (reply_error(req, 400, "invalid", "a user's name"));
	if (req->method == HTTP_METHOD_GET) {
		if ((o = pstore_load(name, etag)) == NULL)
			return (reply_error(req, 404, "not_found", "nothing is "
			    "stored"));
		http_response_header(req, "etag", etag);
		return (reply_json(req, 200, o));
	}
	if (shared && user_console(user) != CROLE_OWNER &&
	    user_console(user) != CROLE_OPERATOR)
		return (reply_error(req, 403, "role", "a plugin's shared store "
		    "is written by an operator or an owner of this console"));
	if ((status = pstore_body(req, &o)) != 0)
		return (reply_error(req, status, status == 413 ? "too_large" :
		    "invalid", status == 413 ? "%d bytes at most" :
		    "a JSON object", PSTORE_MAX));
	/* {"arcana-console:<store>": {...}}. */
	if ((o = cyang_unwrap(req, o)) == NULL)
		return (reply_error(req, 400, "invalid", "{\"arcana-console:"
		    "%s\": a JSON object}", shared ? "shared-store" : "store"));
	if ((len = pstore_tag(o, etag)) == -1 || len > PSTORE_MAX) {
		ucl_object_unref(o);
		return (len == -1 ? reply_error(req, 500, "store", "out of "
		    "memory") : reply_error(req, 413, "too_large", "%d bytes at "
		    "most", PSTORE_MAX));
	}
	fd = pstore_lock();
	cur = pstore_load(name, now);
	if (http_request_header(req, "if-match", &v))
		ok = cur != NULL && (strcmp(v, "*") == 0 || strcmp(v, now) == 0);
	else
		ok = cur == NULL;
	if (cur != NULL)
		ucl_object_unref(cur);
	if (!ok) {
		pstore_unlock(fd);
		ucl_object_unref(o);
		return (reply_error(req, 412, "changed", "the store is not what "
		    "the tag given says: read it again"));
	}
	status = store_save(name, o);
	pstore_unlock(fd);
	ucl_object_unref(o);
	if (status != 0)
		return (reply_error(req, 500, "store", "%s could not be "
		    "written", name));
	http_response_header(req, "etag", etag);
	top = ucl_object_typed_new(UCL_OBJECT);
	put(top, "etag", ucl_object_fromstring(etag));
	return (reply_json(req, 200, top));
}

/* A user gone (users.c): their stores, of every plugin, with them. */
void
cplug_store_forget(const char *user)
{
	DIR		*d;
	struct dirent	*e;
	char		 u[PSTORE_USER], tail[PSTORE_USER + 16];
	char		 path[MAXPATHLEN], name[MAXPATHLEN];
	size_t		 n, t;
	int		 fd;

	if (!pstore_user(user, u, sizeof(u)))
		return;
	snprintf(tail, sizeof(tail), ".user.%s.json", u);
	t = strlen(tail);
	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, PSTORE_DIR);
	if ((d = opendir(path)) == NULL)
		return;
	fd = pstore_lock();
	while ((e = readdir(d)) != NULL) {
		/* <id> has no dot: the first is the tail's. */
		n = strlen(e->d_name);
		if (e->d_type != DT_REG || n <= t || strcmp(e->d_name + n - t,
		    tail) != 0 || strchr(e->d_name, '.') != e->d_name + n - t)
			continue;
		snprintf(name, sizeof(name), "%s/%s", PSTORE_DIR, e->d_name);
		if (store_remove(name) != 0)
			log_msg(LOG_ERR, "%s: not removed with user %s", name,
			    user);
	}
	pstore_unlock(fd);
	closedir(d);
}
