/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * hist: history.c's looks over interfaces the test makes come and go,
 * for agent_test.sh.  getifaddrs(3) is this program's: at look r there
 * are em0, which moves nothing, and epair<r>a, there for that look and
 * the one after, which moves 1000 bytes in and out between them; every
 * look the epairs of the looks before are gone.  With "wide" (argv[3]),
 * em0 and twenty epairs at every look, each moving 1000 bytes in and
 * out between two.  After argv[1] looks
 * (argv[2] the history file, sampling off so no thread looks) the
 * samples are written, and the head's interfaces and the last row's
 * total in and out printed:
 *
 *	nets em0 epair...
 *	rx <bytes a second> tx <bytes a second>
 *	placed rx <the placed interfaces' in, together>
 */

#include <sys/param.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/if_dl.h>

#include <err.h>
#include <ifaddrs.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "agent.h"

struct opts	opts;
static int	round;
static bool	wide;

/* The interfaces of the look under way. */
int
getifaddrs(struct ifaddrs **ap)
{
	struct ifaddrs		*v;
	struct sockaddr_dl	*sdl;
	struct if_data		*d;
	int			 i, n = wide ? 21 : 3;

	if ((v = calloc((size_t)n, sizeof(*v))) == NULL ||
	    (sdl = calloc((size_t)n, sizeof(*sdl))) == NULL ||
	    (d = calloc((size_t)n, sizeof(*d))) == NULL)
		return (-1);
	for (i = 0; i < n; i++) {
		sdl[i].sdl_family = AF_LINK;
		sdl[i].sdl_len = sizeof(sdl[i]);
		v[i].ifa_addr = (struct sockaddr *)&sdl[i];
		v[i].ifa_data = &d[i];
		v[i].ifa_name = malloc(IFNAMSIZ);
		v[i].ifa_next = i + 1 < n ? &v[i + 1] : NULL;
	}
	snprintf(v[0].ifa_name, IFNAMSIZ, "em0");
	/* Wide: twenty epairs at once, each 1000 bytes more each look. */
	if (wide) {
		for (i = 1; i < n; i++) {
			snprintf(v[i].ifa_name, IFNAMSIZ, "epair%da", i);
			d[i].ifi_ibytes = d[i].ifi_obytes = (uint64_t)round *
			    1000;
		}
		*ap = v;
		return (0);
	}
	/* The epair of this look, at its start; and the one before, which
	 * moved since. */
	snprintf(v[1].ifa_name, IFNAMSIZ, "epair%da", round);
	snprintf(v[2].ifa_name, IFNAMSIZ, "epair%da", round - 1);
	d[2].ifi_ibytes = d[2].ifi_obytes = 1000;
	*ap = v;
	return (0);
}

void
freeifaddrs(struct ifaddrs *v)
{
	struct ifaddrs	*i;

	for (i = v; i != NULL; i = i->ifa_next)
		free(i->ifa_name);
	free(v->ifa_addr);
	free(v->ifa_data);
	free(v);
}

size_t
speeder_rates(struct speeder_rate *v __unused, size_t max __unused,
    unsigned int s __unused)
{

	return (0);
}

void
event_add(const char *kind __unused, const char *fmt __unused, ...)
{
}

const char *
json_quote(const char *s, char *buf, size_t len)
{

	strlcpy(buf, s, len);
	return (buf);
}

void
fault_set(const char *type __unused, const char *sev __unused,
    const char *obj __unused, const char *by __unused,
    const char *fmt __unused, ...)
{
}

void
fault_clear(const char *type __unused, const char *obj __unused,
    const char *fmt __unused, ...)
{
}

int
fault_reconcile(const char *by __unused, const char *type __unused,
    const char *const *scope __unused, struct fault_live *v, size_t n,
    const char *why __unused)
{

	while (n-- > 0)
		v[n].open = false;
	return (0);
}

void
logmsg(int level __unused, const char *fmt __unused, ...)
{
}

/* Storage is not looked at: zpool(8) not run. */
int
run_exec(struct work *w __unused, char *const argv[] __unused,
    struct execres *r __unused)
{

	return (-1);
}

void
work_init(struct work *w)
{

	memset(w, 0, sizeof(*w));
}

void
work_free(struct work *w __unused)
{
}

char *
wstrndup(struct work *w __unused, const char *s, size_t n)
{

	return (strndup(s, n));
}

char *
wfmt(struct work *w __unused, const char *fmt __unused, ...)
{

	return (NULL);
}

const char *
wtext(struct work *w __unused, const char *s)
{

	return (s);
}

void *
wadopt(struct work *w __unused, void *p)
{

	return (p);
}

int
step_begin(struct work *w __unused, uint8_t k __unused,
    const char *n __unused, const char *fmt __unused, ...)
{

	return (0);
}

void
step_end(struct work *w __unused, int s __unused, bool ok __unused,
    const char *fmt __unused, ...)
{
}

int
main(int argc, char **argv)
{
	char	path[MAXPATHLEN], *line = NULL, *last = NULL, *f;
	size_t	cap = 0;
	FILE	*fp;
	double	sum;
	int	n, i, k;

	if ((argc != 3 && (argc != 4 || strcmp(argv[3], "wide") != 0)) ||
	    (n = atoi(argv[1])) < 2)
		errx(1, "usage: hist looks history-file [wide]");
	wide = argc == 4;
	opts.history_conf = argv[2];
	opts.zpool_bin = "/nonexistent";
	if ((fp = fopen(argv[2], "w")) == NULL)
		err(1, "%s", argv[2]);
	fprintf(fp, "step=1\nkeep=100\nstorage=0\nenabled=no\n");
	fclose(fp);
	history_start();
	for (round = 1; round <= n; round++)
		history_look();
	history_save();
	snprintf(path, sizeof(path), "%s.samples", argv[2]);
	if ((fp = fopen(path, "r")) == NULL)
		err(1, "%s", path);
	for (i = 0; getline(&line, &cap, fp) != -1; i++) {
		if (i == 1) {
			line[strcspn(line, "|")] = '\0';
			printf("nets");
			strtok(line, " ");
			strtok(NULL, " ");
			while ((f = strtok(NULL, " ")) != NULL)
				printf(" %s", f);
			printf("\n");
		} else if (i > 1) {
			free(last);
			last = strdup(line);
		}
	}
	fclose(fp);
	if (last == NULL)
		errx(1, "no samples");
	/* t cpu load mem swap rx tx read write, then each interface's in
	 * and out: the totals, and the sum of the placed ones' in. */
	sum = 0;
	for (k = 0, f = strtok(last, " "); f != NULL; k++, f = strtok(NULL,
	    " ")) {
		if (k == 5)
			printf("rx %s", f);
		else if (k == 6)
			printf(" tx %s", f);
		else if (k >= 9 && (k - 9) % 2 == 0)
			sum += strtod(f, NULL);
	}
	printf("\nplaced rx %.0f\n", sum);
	free(line);
	return (0);
}
