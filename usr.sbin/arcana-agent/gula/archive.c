/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Gula: the archive, the long run of what the host was sampled at
 * (PLAN-SDN-YANG 5.6.3), on its disk beside the history the sampler
 * keeps in memory.  history.c gives it each look's row, the prober
 * (probe_pm.c) each target's eval interval; the console reads it
 * through arcana-history's read-archive (yarchive.c).
 *
 * Six classes, each its series: host (one: CPU, load, memory, swap and
 * the totals in, out, read and written), interface, disk, jail and
 * relay (one each the sampler tells apart) and probe (one a target, by
 * its name).  A class's step is the seconds a point stands for: the
 * samples within a bucket of it are merged (the mean of each figure,
 * the least of the least, the most of the most, the sum of the
 * counts; a figure not told, below zero, left out), the bucket written
 * when a sample of a later one comes, and at the agent's stop.  Its
 * retention is in days, and the archive as a whole has a budget: over
 * it, the oldest day of any class goes first; a class whose day under
 * way alone keeps it over is stopped until the next day.
 *
 * On disk a class's day (UTC) is a file, <class>/YYYYMMDD.arc, so
 * that what goes, goes a file at a time.  A magic, then records: each
 * its payload's length as a varint, the payload, and the payload's
 * CRC-32 (four bytes, little-endian).  A payload begins with its type:
 *
 *	S id name		a series named, once in a file: its number
 *				(a varint) and its name (a varint length,
 *				the bytes)
 *	B t n {id v...}		a bucket: its time, in seconds into the
 *				day; then n series, each its number and
 *				each figure as an integer (the figure
 *				times its field's scale), zigzag varint of
 *				its difference from the series' point
 *				before in the file
 *
 * A file reads alone from its start.  A record is written whole by one
 * write(2), and fsync(2) follows every ARC_SYNC seconds and at the
 * stop; at the start today's file is read through and cut where a
 * record is not whole (what a power lost leaves at its end), and a
 * file whose magic is not this one's is put aside (.bad).
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>

#include "agent.h"

#define	ARC_MAGIC	"ARCARCH1"
#define	ARC_MAGIC_LEN	8
#define	ARC_SERIES_MAX	1024		/* a class's series, a file */
#define	ARC_NAME_MAX	255
#define	ARC_REC_MAX	(256 * 1024)	/* a payload, at most */
#define	ARC_SYNC	300		/* s between two fsyncs */
#define	ARC_DAY		86400
#define	ARC_READ_MAX	100000		/* points a read gives, all told */
#define	ARC_FILE_MAX	(64 * 1024 * 1024)	/* a day's file read whole */

enum { AG_MEAN, AG_MIN, AG_MAX, AG_SUM };

static const char *const f_host[] = { "cpu", "load", "memory", "swap",
    "received", "sent", "read", "written" };
static const uint32_t s_host[] = { 10, 100, 1, 1, 1, 1, 1, 1 };
static const uint8_t a_host[] = { AG_MEAN, AG_MEAN, AG_MEAN, AG_MEAN,
    AG_MEAN, AG_MEAN, AG_MEAN, AG_MEAN };
static const char *const f_if[] = { "received", "sent" };
static const char *const f_disk[] = { "read", "written" };
static const char *const f_jail[] = { "cpu", "memory" };
static const char *const f_relay[] = { "plain", "added" };
static const uint32_t s_one[] = { 1, 1 };
static const uint32_t s_jail[] = { 10, 1 };
static const uint8_t a_two[] = { AG_MEAN, AG_MEAN };
static const char *const f_probe[] = { "delay", "ipdv", "loss", "min",
    "max", "lost-forward", "lost-backward", "delay-forward",
    "delay-backward", "sent", "received" };
static const uint32_t s_probe[] = { 1000, 1000, 10000, 1000, 1000, 10000,
    10000, 1000, 1000, 1, 1 };
static const uint8_t a_probe[] = { AG_MEAN, AG_MEAN, AG_MEAN, AG_MIN,
    AG_MAX, AG_MEAN, AG_MEAN, AG_MEAN, AG_MEAN, AG_SUM, AG_SUM };

static const struct cdef {
	const char		*name;
	size_t			 ncols;
	const char *const	*fields;
	const uint32_t		*scale;
	const uint8_t		*agg;
	unsigned int		 keep;		/* days, unless set */
} cdefs[ARC_CLASSES] = {
	{ "host", nitems(f_host), f_host, s_host, a_host, 30 },
	{ "interface", 2, f_if, s_one, a_two, 7 },
	{ "disk", 2, f_disk, s_one, a_two, 7 },
	{ "jail", 2, f_jail, s_jail, a_two, 7 },
	{ "relay", 2, f_relay, s_one, a_two, 7 },
	{ "probe", nitems(f_probe), f_probe, s_probe, a_probe, 7 },
};

/* A series as the writer has it: its number in today's file (-1 not
 * named there yet), its point before there, and the bucket under way. */
struct aseries {
	char		*name;
	int		 id;
	int64_t		 last[ARC_COLS_MAX];
	double		 acc[ARC_COLS_MAX];
	unsigned int	 n[ARC_COLS_MAX];	/* figures told */
	unsigned int	 samples;
};

struct aclass {
	struct aseries	*s;
	size_t		 ns, cap;
	size_t		 hint;		/* the series looked for next, likely */
	int		 fd;		/* today's file, -1 none */
	long		 day;		/* its day, since the epoch */
	int		 nid;		/* series named in it */
	time_t		 bucket;	/* under way; 0 none */
	bool		 full;		/* over the budget until the next day */
	bool		 dirty;		/* written since the last fsync */
	time_t		 synced;	/* monotonic */
	unsigned long	 dropped;	/* samples older than the bucket */
};

/* A growing buffer of bytes. */
struct abuf {
	unsigned char	*p;
	size_t		 len, cap;
	bool		 bad;		/* out of memory */
};

static pthread_mutex_t	arc_lock = PTHREAD_MUTEX_INITIALIZER;
static struct arc_conf	conf = { .on = true, .budget = ARC_BUDGET };
static struct aclass	classes[ARC_CLASSES];
static bool		arc_ok;		/* its directory there */
static uint64_t		total;		/* every file's bytes */
static bool		started;

static time_t
arc_mono(void)
{
	struct timespec	ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (ts.tv_sec);
}

static unsigned int
cstep(int c)
{

	return (conf.step[c] != 0 ? conf.step[c] : ARC_STEP);
}

static unsigned int
ckeep(int c)
{

	return (conf.keep[c] != 0 ? conf.keep[c] : cdefs[c].keep);
}

/* ---- Bytes ---------------------------------------------------------- */

static void
put_byte(struct abuf *b, unsigned char c)
{
	unsigned char	*np;
	size_t		 ncap;

	if (b->bad)
		return;
	if (b->len == b->cap) {
		ncap = b->cap == 0 ? 256 : b->cap * 2;
		if ((np = realloc(b->p, ncap)) == NULL) {
			b->bad = true;
			return;
		}
		b->p = np;
		b->cap = ncap;
	}
	b->p[b->len++] = c;
}

static void
put_uvar(struct abuf *b, uint64_t v)
{

	while (v >= 0x80) {
		put_byte(b, (unsigned char)(v | 0x80));
		v >>= 7;
	}
	put_byte(b, (unsigned char)v);
}

static void
put_svar(struct abuf *b, int64_t v)
{

	put_uvar(b, ((uint64_t)v << 1) ^ (uint64_t)(v >> 63));
}

/* A varint at *pp, before end; false when it is not whole or longer
 * than 64 bits. */
static bool
get_uvar(const unsigned char **pp, const unsigned char *end, uint64_t *v)
{
	const unsigned char	*p = *pp;
	unsigned int		 shift;

	*v = 0;
	for (shift = 0; p < end && shift < 64; shift += 7) {
		*v |= (uint64_t)(*p & 0x7f) << shift;
		if ((*p++ & 0x80) == 0) {
			*pp = p;
			return (true);
		}
	}
	return (false);
}

static bool
get_svar(const unsigned char **pp, const unsigned char *end, int64_t *v)
{
	uint64_t	u;

	if (!get_uvar(pp, end, &u))
		return (false);
	*v = (int64_t)(u >> 1) ^ -(int64_t)(u & 1);
	return (true);
}

/* A record of payload pl (len bytes) framed into b: its length, it,
 * its CRC. */
static void
put_record(struct abuf *b, const struct abuf *pl)
{
	uLong	crc;
	int	i;

	put_uvar(b, pl->len);
	for (size_t k = 0; k < pl->len; k++)
		put_byte(b, pl->p[k]);
	crc = crc32(0L, pl->p, (uInt)pl->len);
	for (i = 0; i < 4; i++)
		put_byte(b, (unsigned char)(crc >> (8 * i)));
}

/* A figure as the integer kept: times its scale, rounded, within what
 * a difference of two of them can say. */
static int64_t
quant(double v, uint32_t scale)
{
	double	q;

	q = round(v * scale);
	if (q > 1e18)
		q = 1e18;
	if (q < -1e18)
		q = -1e18;
	return ((int64_t)q);
}

/* ---- Files ---------------------------------------------------------- */

static void
day_path(char *buf, size_t len, int c, long day)
{
	struct tm	tm;
	time_t		t = (time_t)day * ARC_DAY;
	char		d[16];

	if (gmtime_r(&t, &tm) == NULL || strftime(d, sizeof(d), "%Y%m%d",
	    &tm) == 0)
		strlcpy(d, "00000000", sizeof(d));
	snprintf(buf, len, "%s/%s/%s.arc", opts.archive_dir, cdefs[c].name, d);
}

/* A file's name as its day, or -1: YYYYMMDD.arc. */
static long
name_day(const char *name)
{
	struct tm	tm;
	const char	*end;
	time_t		t;

	if (strlen(name) != 12 || strcmp(name + 8, ".arc") != 0)
		return (-1);
	memset(&tm, 0, sizeof(tm));
	end = strptime(name, "%Y%m%d", &tm);
	if (end == NULL || end != name + 8)
		return (-1);
	if ((t = timegm(&tm)) == -1 || t < 0)
		return (-1);
	return ((long)(t / ARC_DAY));
}

/*
 * What a file's bytes say, read through: each series named, and each
 * bucket's points given to fn (its series' number and name, the time,
 * the integers kept).  The length of what is whole, from the start;
 * the magic not there, -1; no memory to read it, -2.
 */
struct adec {
	char		*names[ARC_SERIES_MAX];
	int64_t		(*last)[ARC_COLS_MAX];
	int		 nid;
};

typedef void	adec_fn(void *, int, const char *, time_t, const int64_t *);

static void
adec_free(struct adec *d)
{

	for (int i = 0; i < d->nid; i++)
		free(d->names[i]);
	free(d->last);
	memset(d, 0, sizeof(*d));
}

static ssize_t
decode(const unsigned char *buf, size_t len, int c, long day,
    struct adec *d, adec_fn *fn, void *arg)
{
	const unsigned char	*p, *rec, *pl, *end;
	uint64_t		 plen, id, nlen, t, n;
	int64_t			 dv, q[ARC_COLS_MAX];
	uint32_t		 crc;
	size_t			 k, ncols = cdefs[c].ncols;
	char			*name;

	memset(d, 0, sizeof(*d));
	if ((d->last = calloc(ARC_SERIES_MAX, sizeof(*d->last))) == NULL)
		return (-2);
	if (len < ARC_MAGIC_LEN || memcmp(buf, ARC_MAGIC, ARC_MAGIC_LEN) != 0)
		return (-1);
	p = buf + ARC_MAGIC_LEN;
	end = buf + len;
	while (p < end) {
		rec = p;
		if (!get_uvar(&p, end, &plen) || plen == 0 || plen >
		    ARC_REC_MAX || (size_t)(end - p) < plen + 4)
			return (rec - buf);
		pl = p;
		p += plen;
		crc = (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] <<
		    16 | (uint32_t)p[3] << 24;
		if (crc != (uint32_t)crc32(0L, pl, (uInt)plen))
			return (rec - buf);
		p += 4;
		switch (*pl++) {
		case 'S':
			if (!get_uvar(&pl, p - 4, &id) || id != (uint64_t)d->nid ||
			    id >= ARC_SERIES_MAX || !get_uvar(&pl, p - 4, &nlen) ||
			    nlen == 0 || nlen > ARC_NAME_MAX || (size_t)(p - 4 -
			    pl) != nlen)
				return (rec - buf);
			if ((name = malloc(nlen + 1)) == NULL)
				return (rec - buf);
			memcpy(name, pl, nlen);
			name[nlen] = '\0';
			d->names[d->nid++] = name;
			break;
		case 'B':
			if (!get_uvar(&pl, p - 4, &t) || t >= ARC_DAY ||
			    !get_uvar(&pl, p - 4, &n) || n > (uint64_t)d->nid)
				return (rec - buf);
			while (n-- > 0) {
				if (!get_uvar(&pl, p - 4, &id) || id >=
				    (uint64_t)d->nid)
					return (rec - buf);
				for (k = 0; k < ncols; k++) {
					if (!get_svar(&pl, p - 4, &dv))
						return (rec - buf);
					d->last[id][k] += dv;
					q[k] = d->last[id][k];
				}
				if (fn != NULL)
					fn(arg, (int)id, d->names[id],
					    (time_t)(day * ARC_DAY + (long)t), q);
			}
			if (pl != p - 4)
				return (rec - buf);
			break;
		default:
			return (rec - buf);
		}
	}
	return (p - buf);
}

/* A file read whole into memory, at most ARC_FILE_MAX; NULL none. */
static unsigned char *
slurp_fd(int fd, size_t *lenp)
{
	struct stat	 st;
	unsigned char	*buf;
	ssize_t		 r;
	size_t		 got;

	if (fstat(fd, &st) == -1 || st.st_size < 0 || st.st_size >
	    ARC_FILE_MAX)
		return (NULL);
	if ((buf = malloc((size_t)st.st_size + 1)) == NULL)
		return (NULL);
	for (got = 0; got < (size_t)st.st_size; got += (size_t)r)
		if ((r = pread(fd, buf + got, (size_t)st.st_size - got,
		    (off_t)got)) <= 0)
			break;
	*lenp = got;
	return (buf);
}

/* The series of c named, made when there is room; NULL else. */
static struct aseries *
series(struct aclass *k, const char *name)
{
	struct aseries	*nv, *s;
	size_t		 i;

	/* The one after the one before first: the prober's targets, and
	 * the sampler's devices, come in the same order each time. */
	if (k->hint < k->ns && strcmp(k->s[k->hint].name, name) == 0)
		return (&k->s[k->hint++]);
	for (i = 0; i < k->ns; i++)
		if (strcmp(k->s[i].name, name) == 0) {
			k->hint = i + 1;
			return (&k->s[i]);
		}
	if (k->ns == ARC_SERIES_MAX)
		return (NULL);
	if (k->ns == k->cap) {
		if ((nv = reallocarray(k->s, k->cap + 16, sizeof(*nv))) ==
		    NULL)
			return (NULL);
		k->s = nv;
		k->cap += 16;
	}
	s = &k->s[k->ns];
	memset(s, 0, sizeof(*s));
	if ((s->name = strdup(name)) == NULL)
		return (NULL);
	s->id = -1;
	k->ns++;
	return (s);
}

static void
file_close(struct aclass *k)
{

	if (k->fd == -1)
		return;
	if (k->dirty)
		(void)fsync(k->fd);
	(void)close(k->fd);
	k->fd = -1;
	k->dirty = false;
}

/*
 * Class c's file of day opened to be written: made with its magic, or
 * read through when it is there, its series and their points before
 * taken up and a record that is not whole cut off.  The series that
 * had no point in the day before are let go.
 */
static bool
file_open(int c, long day)
{
	struct aclass	*k = &classes[c];
	struct adec	 d;
	struct aseries	*s;
	unsigned char	*buf;
	char		 path[MAXPATHLEN], bad[MAXPATHLEN + 4];
	size_t		 len, i, n;
	ssize_t		 whole;
	int		 fd;

	file_close(k);
	for (i = n = 0; i < k->ns; i++) {
		if (k->s[i].id == -1 && k->s[i].samples == 0) {
			free(k->s[i].name);
			continue;
		}
		k->s[n] = k->s[i];
		k->s[n].id = -1;
		memset(k->s[n].last, 0, sizeof(k->s[n].last));
		n++;
	}
	k->ns = n;
	k->nid = 0;
	k->day = day;
	day_path(path, sizeof(path), c, day);
	if ((fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600)) == -1) {
		logmsg(LOG_WARNING, "archive: %s: %s", path, strerror(errno));
		return (false);
	}
	if ((buf = slurp_fd(fd, &len)) == NULL) {
		logmsg(LOG_WARNING, "archive: %s: not read", path);
		(void)close(fd);
		return (false);
	}
	if (len == 0) {
		free(buf);
		if (write(fd, ARC_MAGIC, ARC_MAGIC_LEN) != ARC_MAGIC_LEN) {
			logmsg(LOG_WARNING, "archive: %s: %s", path,
			    strerror(errno));
			(void)close(fd);
			return (false);
		}
		total += ARC_MAGIC_LEN;
		k->fd = fd;
		k->dirty = true;
		return (true);
	}
	whole = decode(buf, len, c, day, &d, NULL, NULL);
	free(buf);
	if (whole == -2) {
		logmsg(LOG_WARNING, "archive: %s: out of memory", path);
		adec_free(&d);
		(void)close(fd);
		return (false);
	}
	if (whole == -1) {
		adec_free(&d);
		(void)close(fd);
		snprintf(bad, sizeof(bad), "%s.bad", path);
		total -= MIN(total, len);
		if (rename(path, bad) == -1) {
			logmsg(LOG_WARNING, "archive: %s is not one; not put "
			    "aside: %s", path, strerror(errno));
			return (false);
		}
		logmsg(LOG_WARNING, "archive: %s is not one: put aside as %s",
		    path, bad);
		return (file_open(c, day));
	}
	if ((size_t)whole < len) {
		logmsg(LOG_WARNING, "archive: %s: %zu bytes at its end not "
		    "whole, cut off", path, len - (size_t)whole);
		if (ftruncate(fd, (off_t)whole) == -1) {
			adec_free(&d);
			(void)close(fd);
			return (false);
		}
		total -= MIN(total, len - (size_t)whole);
	}
	for (i = 0; i < (size_t)d.nid; i++) {
		if ((s = series(k, d.names[i])) == NULL)
			continue;
		s->id = (int)i;
		memcpy(s->last, d.last[i], sizeof(s->last));
	}
	k->nid = d.nid;
	adec_free(&d);
	if (lseek(fd, 0, SEEK_END) == -1) {
		(void)close(fd);
		return (false);
	}
	k->fd = fd;
	return (true);
}

/* ---- Retention and the budget --------------------------------------- */

struct afile {
	int		 c;
	long		 day;
	uint64_t	 bytes;
};

static int
afile_cmp(const void *a, const void *b)
{
	const struct afile	*x = a, *y = b;

	if (x->day != y->day)
		return (x->day < y->day ? -1 : 1);
	return (x->bytes > y->bytes ? -1 : x->bytes < y->bytes);
}

/* Every class's files, oldest first; their bytes into total. */
static struct afile *
files_list(size_t *np)
{
	struct afile	*v = NULL, *nv;
	struct dirent	*de;
	struct stat	 st;
	DIR		*dir;
	char		 path[MAXPATHLEN];
	size_t		 n = 0, cap = 0;
	long		 day;
	int		 c;

	total = 0;
	for (c = 0; c < ARC_CLASSES; c++) {
		snprintf(path, sizeof(path), "%s/%s", opts.archive_dir,
		    cdefs[c].name);
		if ((dir = opendir(path)) == NULL)
			continue;
		while ((de = readdir(dir)) != NULL) {
			if ((day = name_day(de->d_name)) == -1 ||
			    fstatat(dirfd(dir), de->d_name, &st,
			    AT_SYMLINK_NOFOLLOW) == -1 || !S_ISREG(st.st_mode))
				continue;
			if (n == cap) {
				if ((nv = reallocarray(v, cap + 64,
				    sizeof(*nv))) == NULL)
					break;
				v = nv;
				cap += 64;
			}
			v[n].c = c;
			v[n].day = day;
			v[n].bytes = (uint64_t)st.st_size;
			total += v[n].bytes;
			n++;
		}
		closedir(dir);
	}
	if (n > 0)
		qsort(v, n, sizeof(*v), afile_cmp);
	*np = n;
	return (v);
}

/*
 * Each class's days kept to its retention, and the whole to the
 * budget: the oldest day of any class first; today's files last, the
 * biggest of them stopped (full) until the next day.
 */
static void
enforce(void)
{
	struct afile	*v;
	char		 path[MAXPATHLEN];
	uint64_t	 budget;
	long		 today;
	size_t		 n, i;
	int		 c, big;

	if (!arc_ok)
		return;
	today = (long)(time(NULL) / ARC_DAY);
	budget = (uint64_t)conf.budget * 1024 * 1024;
	v = files_list(&n);
	for (i = 0; i < n; i++) {
		c = v[i].c;
		if (v[i].day > today - (long)ckeep(c) && total <= budget)
			continue;
		/* Today's own goes no more than by its retention. */
		if (classes[c].fd != -1 && v[i].day == classes[c].day &&
		    v[i].day > today - (long)ckeep(c))
			continue;
		if (classes[c].fd != -1 && v[i].day == classes[c].day)
			file_close(&classes[c]);
		day_path(path, sizeof(path), c, v[i].day);
		if (unlink(path) == -1)
			continue;
		if (v[i].day > today - (long)ckeep(c))
			logmsg(LOG_NOTICE, "archive: over its budget of %u "
			    "MiB: %s let go", conf.budget, path);
		total -= MIN(total, v[i].bytes);
	}
	free(v);
	/* Today's alone over it: the biggest stopped; a write still over
	 * it stops the next. */
	if (total <= budget)
		return;
	big = -1;
	v = files_list(&n);
	for (i = 0; i < n; i++)
		if (classes[v[i].c].fd != -1 && v[i].day ==
		    classes[v[i].c].day && (big == -1 || v[i].bytes >
		    v[big].bytes))
			big = (int)i;
	if (big != -1) {
		c = v[big].c;
		file_close(&classes[c]);
		classes[c].full = true;
		logmsg(LOG_WARNING, "archive: over its budget of %u MiB with "
		    "today's alone: %s kept no more until tomorrow",
		    conf.budget, cdefs[c].name);
	}
	free(v);
}

/* ---- Writing -------------------------------------------------------- */

/*
 * Class c's bucket under way written, as a block of each series that
 * has a point, the series not yet named in the file named first; then
 * fsync(2) when it is due (or now).
 */
static void
flush(int c, bool now)
{
	struct aclass	*k = &classes[c];
	const struct cdef *d = &cdefs[c];
	struct aseries	*s;
	struct abuf	 out = { 0 }, pl = { 0 }, blk = { 0 };
	unsigned int	 nser;
	long		 day;
	double		 v;
	int64_t		 q;
	size_t		 i, j;
	ssize_t		 w;

	if (k->bucket == 0)
		goto sync;
	for (i = nser = 0; i < k->ns; i++)
		if (k->s[i].samples > 0)
			nser++;
	if (nser == 0)
		goto sync;
	day = (long)(k->bucket / ARC_DAY);
	if (k->full && day != k->day)
		k->full = false;
	if (k->full || !arc_ok || (day != k->day || k->fd == -1 ? !file_open(c,
	    day) : false)) {
		for (i = 0; i < k->ns; i++)
			k->s[i].samples = 0;
		goto sync;
	}
	put_byte(&blk, 'B');
	put_uvar(&blk, (uint64_t)(k->bucket - (time_t)day * ARC_DAY));
	nser = 0;
	for (i = 0; i < k->ns; i++) {
		s = &k->s[i];
		if (s->samples == 0 || (s->id == -1 && k->nid == ARC_SERIES_MAX))
			continue;
		if (s->id == -1) {
			pl.len = 0;
			put_byte(&pl, 'S');
			put_uvar(&pl, (uint64_t)k->nid);
			put_uvar(&pl, strlen(s->name));
			for (j = 0; s->name[j] != '\0'; j++)
				put_byte(&pl, (unsigned char)s->name[j]);
			put_record(&out, &pl);
			s->id = k->nid++;
		}
		nser++;
	}
	put_uvar(&blk, nser);
	for (i = 0; i < k->ns; i++) {
		s = &k->s[i];
		if (s->samples == 0 || s->id == -1)
			continue;
		put_uvar(&blk, (uint64_t)s->id);
		for (j = 0; j < d->ncols; j++) {
			if (s->n[j] == 0)
				v = -1;
			else if (d->agg[j] == AG_MEAN)
				v = s->acc[j] / s->n[j];
			else
				v = s->acc[j];
			q = quant(v, d->scale[j]);
			put_svar(&blk, q - s->last[j]);
			s->last[j] = q;
		}
	}
	for (i = 0; i < k->ns; i++) {
		s = &k->s[i];
		s->samples = 0;
		memset(s->acc, 0, sizeof(s->acc));
		memset(s->n, 0, sizeof(s->n));
	}
	put_record(&out, &blk);
	if (out.bad || blk.bad || pl.bad) {
		logmsg(LOG_WARNING, "archive: %s: out of memory", d->name);
		goto out;
	}
	if ((w = write(k->fd, out.p, out.len)) != (ssize_t)out.len) {
		logmsg(LOG_WARNING, "archive: %s: %s", d->name, w == -1 ?
		    strerror(errno) : "written short");
		/* What went out not whole is cut at the next start. */
		file_close(k);
		goto out;
	}
	total += out.len;
	k->dirty = true;
	if (total > (uint64_t)conf.budget * 1024 * 1024)
		enforce();
out:
	free(out.p);
	free(pl.p);
	free(blk.p);
sync:
	if (k->fd != -1 && k->dirty && (now || arc_mono() - k->synced >=
	    ARC_SYNC)) {
		(void)fsync(k->fd);
		k->dirty = false;
		k->synced = arc_mono();
	}
}

/*
 * A sample of class c's series named, taken at t (the wall clock):
 * into its bucket, the class's bucket before written when this one is
 * of a later.  One older than the bucket under way (the clock stepped
 * back) is left out.
 */
void
archive_add(int c, const char *name, time_t t, const double *v, size_t n)
{
	struct aclass	*k;
	struct aseries	*s;
	const uint8_t	*agg;
	time_t		 b;
	size_t		 j;

	if (c < 0 || c >= ARC_CLASSES || name == NULL || name[0] == '\0' ||
	    strlen(name) > ARC_NAME_MAX || n != cdefs[c].ncols || t <= 0)
		return;
	pthread_mutex_lock(&arc_lock);
	if (!started || !arc_ok || !conf.on) {
		pthread_mutex_unlock(&arc_lock);
		return;
	}
	k = &classes[c];
	b = t - t % (time_t)cstep(c);
	if (k->bucket != 0 && b < k->bucket) {
		k->dropped++;
		pthread_mutex_unlock(&arc_lock);
		return;
	}
	if (b > k->bucket) {
		flush(c, false);
		k->bucket = b;
	}
	if ((s = series(k, name)) == NULL) {
		pthread_mutex_unlock(&arc_lock);
		return;
	}
	agg = cdefs[c].agg;
	for (j = 0; j < n; j++) {
		/* Not told, or not a number: left out. */
		if (!(v[j] >= 0) || !isfinite(v[j]))
			continue;
		switch (agg[j]) {
		case AG_MIN:
			if (s->n[j] == 0 || v[j] < s->acc[j])
				s->acc[j] = v[j];
			break;
		case AG_MAX:
			if (s->n[j] == 0 || v[j] > s->acc[j])
				s->acc[j] = v[j];
			break;
		default:
			s->acc[j] += v[j];
			break;
		}
		s->n[j]++;
	}
	s->samples++;
	pthread_mutex_unlock(&arc_lock);
}

/* Written down: each class's file synced, and at the stop its bucket
 * under way written first. */
void
archive_sync(bool stop)
{
	int	c;

	pthread_mutex_lock(&arc_lock);
	for (c = 0; started && c < ARC_CLASSES; c++) {
		if (stop) {
			flush(c, true);
			classes[c].bucket = 0;
		} else if (classes[c].fd != -1 && classes[c].dirty) {
			(void)fsync(classes[c].fd);
			classes[c].dirty = false;
			classes[c].synced = arc_mono();
		}
	}
	pthread_mutex_unlock(&arc_lock);
}

/* A directory made with those above it, mode 0700 where it is made. */
static bool
mkdirs(const char *path)
{
	char	buf[MAXPATHLEN], *p;

	if (strlcpy(buf, path, sizeof(buf)) >= sizeof(buf))
		return (false);
	for (p = buf + 1; *p != '\0'; p++) {
		if (*p != '/')
			continue;
		*p = '\0';
		if (mkdir(buf, 0755) == -1 && errno != EEXIST)
			return (false);
		*p = '/';
	}
	return (mkdir(buf, 0700) == 0 || errno == EEXIST);
}

/*
 * Begun: the directory and each class's made, today's files opened as
 * samples come, the days past their retention let go.  After
 * history.conf is read (its archive settings, archive_conf_line()).
 */
void
archive_start(void)
{
	static char	beside[MAXPATHLEN];
	const char	*slash;
	char		 path[MAXPATHLEN];
	int		 c;

	/* Unless --archive says, beside history.conf, as the agent's other
	 * state is (the samples, the probes' targets): a test's own. */
	if (opts.archive_dir == NULL && opts.history_conf != NULL) {
		if (opts.history_conf[0] == '/' || getcwd(path,
		    sizeof(path)) == NULL)
			path[0] = '\0';
		slash = strrchr(opts.history_conf, '/');
		snprintf(beside, sizeof(beside), "%s%s%.*s%sarchive", path,
		    path[0] != '\0' ? "/" : "", slash != NULL ? (int)(slash -
		    opts.history_conf) : 0, opts.history_conf, slash != NULL ?
		    "/" : "");
		opts.archive_dir = beside;
	}
	pthread_mutex_lock(&arc_lock);
	for (c = 0; c < ARC_CLASSES; c++) {
		classes[c].fd = -1;
		classes[c].day = -1;
	}
	started = true;
	arc_ok = opts.archive_dir != NULL && opts.archive_dir[0] == '/' &&
	    mkdirs(opts.archive_dir);
	for (c = 0; arc_ok && c < ARC_CLASSES; c++) {
		snprintf(path, sizeof(path), "%s/%s", opts.archive_dir,
		    cdefs[c].name);
		if (mkdir(path, 0700) == -1 && errno != EEXIST)
			arc_ok = false;
	}
	if (!arc_ok)
		logmsg(LOG_WARNING, "archive: %s: %s; nothing is archived",
		    opts.archive_dir != NULL ? opts.archive_dir : "none",
		    strerror(errno));
	else if (conf.on)
		enforce();
	pthread_mutex_unlock(&arc_lock);
}

/* ---- Settings ------------------------------------------------------- */

const char *
archive_class_name(int c)
{

	return (c >= 0 && c < ARC_CLASSES ? cdefs[c].name : NULL);
}

int
archive_class(const char *name)
{

	for (int c = 0; c < ARC_CLASSES; c++)
		if (strcmp(cdefs[c].name, name) == 0)
			return (c);
	return (-1);
}

unsigned int
archive_default_keep(int c)
{

	return (c >= 0 && c < ARC_CLASSES ? cdefs[c].keep : 0);
}

/* A line of history.conf: archive=yes|no, budget=MiB,
 * class=name:step:retention.  false when it is none of them. */
bool
archive_conf_line(const char *line)
{
	const char	*e;
	char		 name[16], *p;
	long long	 v;
	unsigned int	 step, keep;
	int		 c;

	pthread_mutex_lock(&arc_lock);
	if (strncmp(line, "archive=", 8) == 0)
		conf.on = strcmp(line + 8, "no") != 0;
	else if (strncmp(line, "budget=", 7) == 0) {
		v = strtonum(line + 7, ARC_BUDGET_MIN, ARC_BUDGET_MAX, &e);
		if (e == NULL)
			conf.budget = (uint32_t)v;
	} else if (strncmp(line, "class=", 6) == 0) {
		if (strlcpy(name, line + 6, sizeof(name)) < sizeof(name) &&
		    (p = strchr(name, ':')) != NULL) {
			*p = '\0';
			if ((c = archive_class(name)) != -1 && sscanf(line + 6 +
			    (p - name) + 1, "%u:%u", &step, &keep) == 2 &&
			    (step == 0 || (step >= ARC_STEP_MIN && step <=
			    ARC_STEP_MAX)) && keep <= ARC_KEEP_MAX) {
				conf.step[c] = (uint16_t)step;
				conf.keep[c] = (uint16_t)keep;
			}
		}
	} else {
		pthread_mutex_unlock(&arc_lock);
		return (false);
	}
	pthread_mutex_unlock(&arc_lock);
	return (true);
}

/* Its settings as history.conf keeps them. */
void
archive_conf_write(FILE *fp)
{
	int	c;

	pthread_mutex_lock(&arc_lock);
	fprintf(fp, "archive=%s\nbudget=%u\n", conf.on ? "yes" : "no",
	    conf.budget);
	for (c = 0; c < ARC_CLASSES; c++)
		if (conf.step[c] != 0 || conf.keep[c] != 0)
			fprintf(fp, "class=%s:%u:%u\n", cdefs[c].name,
			    conf.step[c], conf.keep[c]);
	pthread_mutex_unlock(&arc_lock);
}

void
archive_conf_get(struct arc_conf *out)
{

	pthread_mutex_lock(&arc_lock);
	*out = conf;
	pthread_mutex_unlock(&arc_lock);
}

/*
 * Its settings changed (each step and retention 0 the class's
 * default): checked, the buckets under way written at the steps they
 * were, the days now past their retention or the budget let go.  NULL,
 * or what is wrong.
 */
const char *
archive_conf_set(const struct arc_conf *in)
{
	int	c;

	if (in->budget < ARC_BUDGET_MIN || in->budget > ARC_BUDGET_MAX)
		return ("the archive's budget is 1 to 1048576 MiB");
	for (c = 0; c < ARC_CLASSES; c++)
		if ((in->step[c] != 0 && (in->step[c] < ARC_STEP_MIN ||
		    in->step[c] > ARC_STEP_MAX)) || in->keep[c] > ARC_KEEP_MAX)
			return ("an archive class's step is 10 to 3600 seconds "
			    "and its retention 1 to 3660 days");
	pthread_mutex_lock(&arc_lock);
	for (c = 0; started && c < ARC_CLASSES; c++) {
		if (cstep(c) != (in->step[c] != 0 ? in->step[c] : ARC_STEP) ||
		    !in->on) {
			flush(c, true);
			classes[c].bucket = 0;
		}
		if (!in->on)
			file_close(&classes[c]);
	}
	conf = *in;
	if (started && conf.on)
		enforce();
	pthread_mutex_unlock(&arc_lock);
	return (NULL);
}

/* ---- State ---------------------------------------------------------- */

void
archive_state(struct arc_state *st)
{
	struct afile	*v;
	size_t		 n, i;
	int		 c;

	memset(st, 0, sizeof(*st));
	pthread_mutex_lock(&arc_lock);
	st->ok = arc_ok;
	st->budget = (uint64_t)conf.budget * 1024 * 1024;
	for (c = 0; c < ARC_CLASSES; c++) {
		st->c[c].oldest = -1;
		st->c[c].full = classes[c].full;
		st->c[c].series = (unsigned int)classes[c].ns;
		st->c[c].step = cstep(c);
		st->c[c].keep = ckeep(c);
	}
	v = arc_ok ? files_list(&n) : NULL;
	for (i = 0; v != NULL && i < n; i++) {
		c = v[i].c;
		st->c[c].bytes += v[i].bytes;
		st->c[c].files++;
		if (st->c[c].oldest == -1 || v[i].day < st->c[c].oldest)
			st->c[c].oldest = v[i].day;
	}
	st->bytes = total;
	free(v);
	pthread_mutex_unlock(&arc_lock);
}

/* ---- Reading -------------------------------------------------------- */

/* A series being read: its buckets' sums and counts of each figure. */
struct rser {
	char		*name;
	double		*acc;		/* nbins * ncols */
	uint32_t	*n;
};

struct rctx {
	int		 c;
	const char	*want;
	time_t		 from, to, step;
	size_t		 nbins;
	struct rser	*s;
	size_t		 ns, cap;
	size_t		 cells;		/* series times bins, all told */
	bool		 over, nomem;
	/* The file's series numbers to this read's (-1 not yet). */
	int		 map[ARC_SERIES_MAX];
};

static void
read_point(void *arg, int id, const char *name, time_t t, const int64_t *q)
{
	struct rctx		*r = arg;
	const struct cdef	*d = &cdefs[r->c];
	struct rser		*s, *nv;
	size_t			 bin, j, i;
	double			*a;
	uint32_t		*n;
	double			 v;

	if (t < r->from || t > r->to || r->over || r->nomem)
		return;
	if (r->want != NULL && strcmp(name, r->want) != 0)
		return;
	if (r->map[id] == -1) {
		for (i = 0; i < r->ns && strcmp(r->s[i].name, name) != 0; i++)
			;
		if (i == r->ns) {
			if (r->cells + r->nbins > ARC_READ_MAX) {
				r->over = true;
				return;
			}
			if (r->ns == r->cap) {
				if ((nv = reallocarray(r->s, r->cap + 16,
				    sizeof(*nv))) == NULL) {
					r->nomem = true;
					return;
				}
				r->s = nv;
				r->cap += 16;
			}
			s = &r->s[r->ns];
			s->name = strdup(name);
			s->acc = calloc(r->nbins * d->ncols, sizeof(*s->acc));
			s->n = calloc(r->nbins * d->ncols, sizeof(*s->n));
			if (s->name == NULL || s->acc == NULL || s->n == NULL) {
				free(s->name);
				free(s->acc);
				free(s->n);
				r->nomem = true;
				return;
			}
			r->ns++;
			r->cells += r->nbins;
		}
		r->map[id] = (int)i;
	}
	s = &r->s[r->map[id]];
	bin = (size_t)((t - r->from) / r->step);
	if (bin >= r->nbins)
		return;
	a = s->acc + bin * d->ncols;
	n = s->n + bin * d->ncols;
	for (j = 0; j < d->ncols; j++) {
		if (q[j] < 0)
			continue;
		v = (double)q[j];
		switch (d->agg[j]) {
		case AG_MIN:
			if (n[j] == 0 || v < a[j])
				a[j] = v;
			break;
		case AG_MAX:
			if (n[j] == 0 || v > a[j])
				a[j] = v;
			break;
		default:
			a[j] += v;
			break;
		}
		n[j]++;
	}
}

void
archive_read_free(struct arc_read *out)
{

	for (size_t i = 0; i < out->ns; i++) {
		free(out->s[i].name);
		free(out->s[i].t);
		free(out->s[i].v);
	}
	free(out->s);
	memset(out, 0, sizeof(*out));
}

/*
 * Class c's points from to to (the series named, or all), each series
 * given at most points of them: the class's buckets merged into
 * buckets of a multiple of its step when there are more, as they were
 * merged when written; a figure none of a bucket's told, -1.  The
 * bucket under way is not written yet, so not read.  0, or an errno
 * with why.
 */
int
archive_read(int c, const char *name, time_t from, time_t to,
    unsigned int points, struct arc_read *out, const char **why)
{
	struct rctx		 r;
	struct adec		 d;
	const struct cdef	*cd;
	unsigned char		*buf;
	char			 path[MAXPATHLEN];
	time_t			 span, base;
	size_t			 len, i, b, j, k, np;
	long			 day;
	int			 fd, error = 0;

	memset(out, 0, sizeof(*out));
	*why = NULL;
	if (c < 0 || c >= ARC_CLASSES) {
		*why = "no such class";
		return (EINVAL);
	}
	if (to < from || points == 0) {
		*why = "from is after to, or no points asked for";
		return (EINVAL);
	}
	cd = &cdefs[c];
	memset(&r, 0, sizeof(r));
	r.c = c;
	r.want = name;
	pthread_mutex_lock(&arc_lock);
	base = cstep(c);
	pthread_mutex_unlock(&arc_lock);
	/* Buckets of a multiple of the step, aligned to it. */
	span = to - from + 1;
	r.step = base;
	if ((span + base - 1) / base > (time_t)points)
		r.step = ((span + (time_t)points - 1) / (time_t)points +
		    base - 1) / base * base;
	r.from = from - from % r.step;
	r.to = to;
	r.nbins = (size_t)((to - r.from) / r.step + 1);
	if (!arc_ok) {
		*why = "nothing is archived: its directory";
		return (ENOENT);
	}
	for (day = (long)(r.from / ARC_DAY); day <= (long)(to / ARC_DAY);
	    day++) {
		day_path(path, sizeof(path), c, day);
		if ((fd = open(path, O_RDONLY | O_CLOEXEC)) == -1)
			continue;
		buf = slurp_fd(fd, &len);
		(void)close(fd);
		if (buf == NULL)
			continue;
		memset(r.map, 0xff, sizeof(r.map));
		(void)decode(buf, len, c, day, &d, read_point, &r);
		adec_free(&d);
		free(buf);
		if (r.over || r.nomem)
			break;
	}
	if (r.over || r.nomem) {
		*why = r.over ? "more points than a read gives: name a series, "
		    "or ask for fewer points" : "out of memory";
		error = r.over ? E2BIG : ENOMEM;
		goto out;
	}
	out->c = c;
	out->ncols = cd->ncols;
	out->fields = cd->fields;
	out->scale = cd->scale;
	out->step = (uint32_t)r.step;
	if (r.ns > 0 && (out->s = calloc(r.ns, sizeof(*out->s))) == NULL) {
		error = ENOMEM;
		goto out;
	}
	for (i = 0; i < r.ns; i++) {
		struct arc_series	*os = &out->s[i];

		os->name = r.s[i].name;
		r.s[i].name = NULL;
		out->ns++;
		for (b = np = 0; b < r.nbins; b++) {
			for (j = 0; j < cd->ncols; j++)
				if (r.s[i].n[b * cd->ncols + j] != 0)
					break;
			if (j < cd->ncols)
				np++;
		}
		if (np > 0 && ((os->t = calloc(np, sizeof(*os->t))) == NULL ||
		    (os->v = calloc(np * cd->ncols, sizeof(*os->v))) == NULL)) {
			error = ENOMEM;
			goto out;
		}
		for (b = k = 0; b < r.nbins; b++) {
			const double	*a = r.s[i].acc + b * cd->ncols;
			const uint32_t	*n = r.s[i].n + b * cd->ncols;

			for (j = 0; j < cd->ncols; j++)
				if (n[j] != 0)
					break;
			if (j == cd->ncols)
				continue;
			os->t[k] = (int64_t)(r.from + (time_t)b * r.step);
			for (j = 0; j < cd->ncols; j++)
				os->v[k * cd->ncols + j] = n[j] == 0 ? -1 :
				    cd->agg[j] == AG_MEAN ? (int64_t)llround(
				    a[j] / n[j]) : (int64_t)a[j];
			k++;
		}
		os->npoints = k;
	}
out:
	for (i = 0; i < r.ns; i++) {
		free(r.s[i].name);
		free(r.s[i].acc);
		free(r.s[i].n);
	}
	free(r.s);
	if (error != 0) {
		if (*why == NULL)
			*why = "out of memory";
		archive_read_free(out);
	}
	return (error);
}
