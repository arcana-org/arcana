/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * arch: gula/archive.c alone, for agent_test.sh.  Its settings as
 * history.conf's lines (-c line, before the command), its directory
 * the command's:
 *
 *	arch [-c line] feed dir
 *		samples from the standard input, "class name t v...", a
 *		line each, then written down as at the agent's stop
 *	arch [-c line] week dir
 *		a week up to now of every class at the sampler's widest:
 *		the host, 16 interfaces, disks, jails and relays every 5
 *		s, 256 probe targets every 10 s, each figure a random
 *		walk; then each class's bytes and the whole's, the budget,
 *		and "fits" or "over"
 *	arch dump dir class [name [from to points]]
 *		the read: "step s", then each series "series name n" and
 *		its points, "t v...", the integers kept
 *	arch state dir
 *		each class's "class bytes files series full"
 */

#include <sys/param.h>

#include <err.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "agent.h"

struct opts	opts;

void
logmsg(int level __unused, const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

static void
feed(void)
{
	char	*line = NULL, *p, *w, *name;
	size_t	 cap = 0, n;
	double	 v[ARC_COLS_MAX];
	time_t	 t;
	int	 c;

	while (getline(&line, &cap, stdin) != -1) {
		line[strcspn(line, "\n")] = '\0';
		p = line;
		if ((w = strsep(&p, " ")) == NULL || (c = archive_class(w)) ==
		    -1 || (name = strsep(&p, " ")) == NULL || (w = strsep(&p,
		    " ")) == NULL)
			errx(1, "not a sample: %s", line);
		t = (time_t)strtoll(w, NULL, 10);
		for (n = 0; n < ARC_COLS_MAX && (w = strsep(&p, " ")) != NULL;
		    n++)
			v[n] = strtod(w, NULL);
		archive_add(c, name, t, v, n);
	}
	free(line);
	archive_sync(true);
}

/* A figure walking at random about where it was, never below lo. */
static double
walk(double *x, double step, double lo)
{

	*x += step * ((double)arc4random_uniform(2001) / 1000.0 - 1.0);
	if (*x < lo)
		*x = lo;
	return (*x);
}

static int
week(void)
{
	static double	 host[8], dev[4][16][2], probe[256][11];
	struct arc_state st;
	char		 name[32];
	double		 v[ARC_COLS_MAX];
	time_t		 now, t, start;
	int		 c, i, j, k;

	for (j = 0; j < 8; j++)
		host[j] = 1000;
	host[0] = 20;
	host[1] = 1;
	for (c = 0; c < 4; c++)
		for (i = 0; i < 16; i++)
			dev[c][i][0] = dev[c][i][1] = 1e6;
	for (i = 0; i < 256; i++)
		for (j = 0; j < 11; j++)
			probe[i][j] = j == 2 || j == 5 || j == 6 ? 0.01 : 20;
	now = time(NULL);
	start = now - 7 * 86400;
	for (t = start; t <= now; t += 5) {
		v[0] = walk(&host[0], 2, 0);
		v[1] = walk(&host[1], 0.05, 0);
		for (j = 2; j < 8; j++)
			v[j] = walk(&host[j], 1e5, 0);
		archive_add(ARC_HOST, "host", t, v, 8);
		for (c = 0; c < 4; c++)
			for (i = 0; i < 16; i++) {
				snprintf(name, sizeof(name), "%s%d", c == 0 ?
				    "igb" : c == 1 ? "nda" : c == 2 ? "jail" :
				    "arcana_relay_", i);
				v[0] = walk(&dev[c][i][0], 1e5, 0);
				v[1] = walk(&dev[c][i][1], 1e5, 0);
				archive_add(ARC_INTERFACE + c, name, t, v, 2);
			}
		if ((t - start) % 10 != 0)
			continue;
		for (i = 0; i < 256; i++) {
			snprintf(name, sizeof(name), "tunnel-%d@edge%d/af%d",
			    i, i % 8, i % 4);
			for (k = 0; k < 11; k++)
				v[k] = k == 2 || k == 5 || k == 6 ?
				    walk(&probe[i][k], 0.002, 0) : k >= 9 ? 100 :
				    walk(&probe[i][k], 0.5, 0.1);
			archive_add(ARC_PROBE, name, t, v, 11);
		}
	}
	archive_sync(true);
	archive_state(&st);
	for (c = 0; c < ARC_CLASSES; c++)
		printf("%s %ju bytes %u files %u series\n",
		    archive_class_name(c), (uintmax_t)st.c[c].bytes,
		    st.c[c].files, st.c[c].series);
	printf("total %ju budget %ju %s\n", (uintmax_t)st.bytes,
	    (uintmax_t)st.budget, st.bytes <= st.budget ? "fits" : "over");
	return (st.bytes <= st.budget ? 0 : 1);
}

static int
dump(int argc, char **argv)
{
	struct arc_read	 r;
	const char	*why, *name = NULL;
	time_t		 from, to;
	unsigned int	 points = 1000;
	size_t		 i, k, j;
	int		 c, error;

	if ((c = archive_class(argv[0])) == -1)
		errx(1, "%s: no such class", argv[0]);
	to = time(NULL) + 86400;
	from = to - 40 * 86400;
	if (argc > 1 && strcmp(argv[1], "-") != 0)
		name = argv[1];
	if (argc > 4) {
		from = (time_t)strtoll(argv[2], NULL, 10);
		to = (time_t)strtoll(argv[3], NULL, 10);
		points = (unsigned int)strtoul(argv[4], NULL, 10);
	}
	if ((error = archive_read(c, name, from, to, points, &r, &why)) != 0) {
		printf("error %s\n", why);
		return (1);
	}
	printf("step %u\n", r.step);
	for (i = 0; i < r.ns; i++) {
		printf("series %s %zu\n", r.s[i].name, r.s[i].npoints);
		for (k = 0; k < r.s[i].npoints; k++) {
			printf("%jd", (intmax_t)r.s[i].t[k]);
			for (j = 0; j < r.ncols; j++)
				printf(" %jd", (intmax_t)r.s[i].v[k * r.ncols +
				    j]);
			printf("\n");
		}
	}
	archive_read_free(&r);
	return (0);
}

int
main(int argc, char **argv)
{
	struct arc_state	st;
	int			ch, c;

	while ((ch = getopt(argc, argv, "c:")) != -1) {
		if (ch != 'c' || !archive_conf_line(optarg))
			errx(1, "usage: arch [-c line] command dir ...");
	}
	argc -= optind;
	argv += optind;
	if (argc < 2)
		errx(1, "usage: arch [-c line] feed|week|dump|state dir ...");
	opts.archive_dir = argv[1];
	archive_start();
	if (strcmp(argv[0], "feed") == 0)
		feed();
	else if (strcmp(argv[0], "week") == 0)
		return (week());
	else if (strcmp(argv[0], "dump") == 0 && argc >= 3)
		return (dump(argc - 2, argv + 2));
	else if (strcmp(argv[0], "state") == 0) {
		archive_state(&st);
		for (c = 0; c < ARC_CLASSES; c++)
			printf("%s %ju %u %u %s\n", archive_class_name(c),
			    (uintmax_t)st.c[c].bytes, st.c[c].files,
			    st.c[c].series, st.c[c].full ? "full" : "-");
	} else
		errx(1, "%s: no such command", argv[0]);
	return (0);
}
