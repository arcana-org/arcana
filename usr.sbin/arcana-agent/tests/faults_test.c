/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * faults: faults.c and events.c alone, for agent_test.sh: what is
 * kept, told and written, with the files and the YANG side stood in
 * for.  argv[1] says what is tried, and what came of it is printed,
 * one line each:
 *
 *	object		a fault of an object longer than 127 characters,
 *			set, cleared and set again
 *	full		the list filled with open faults, one more, a
 *			clearing, one more
 *	evict		the list full of open and cleared ones, one more
 *	burst		a hundred set at once: how often they are written
 *	control FILE	the alarms' control in FILE taken, kept or not
 *	reconcile	an owner's faults held to what it watches
 *	events		an event of a string with quotes, and one that is
 *			no JSON
 */

#include <sys/param.h>

#include <err.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <ucl.h>

#include "agent.h"

struct opts	opts;
static int	writes;
static char	*kept;
static bool	quiet;

int
sdwan_conf_write(const char *file, const char *text, const char **errp)
{

	(void)errp;
	if (strcmp(file, "sdwan-faults.json") == 0) {
		writes++;
		free(kept);
		kept = strdup(text);
	}
	return (0);
}

char *
sdwan_kept_read(const char *file __unused)
{

	return (NULL);
}

void
logmsg(int level __unused, const char *fmt, ...)
{
	va_list	ap;

	if (quiet)
		return;
	printf("log ");
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
}

void
yang_changed(int what __unused)
{
}

void
yang_event_changed(const char *kind __unused, bool jailed __unused)
{
}

/* What the subscribers are told: each event, as kept. */
void
yang_event(const char *json)
{

	if (!quiet)
		printf("told %s\n", json);
}

int
step_begin(struct work *w __unused, uint8_t kind __unused,
    const char *name __unused, const char *fmt __unused, ...)
{

	return (0);
}

void
step_end(struct work *w __unused, int step __unused, bool ok __unused,
    const char *fmt __unused, ...)
{
}

void *
wadopt(struct work *w __unused, void *p)
{

	return (p);
}

/* The faults as faults_json() gives them: how many, open and not. */
static void
count(const char *what)
{
	ucl_object_t		*top;
	const ucl_object_t	*o;
	ucl_object_iter_t	 it = NULL;
	int			 open = 0, cleared = 0, full = 0;

	top = ucl_object_typed_new(UCL_OBJECT);
	faults_json(top);
	while ((o = ucl_object_iterate(ucl_object_lookup(top, "faults"), &it,
	    true)) != NULL) {
		if (ucl_object_toboolean(ucl_object_lookup(o, "cleared")))
			cleared++;
		else
			open++;
		if (strcmp(ucl_object_tostring(ucl_object_lookup(o, "type")),
		    "alarm-list-full") == 0 && !ucl_object_toboolean(
		    ucl_object_lookup(o, "cleared")))
			full++;
	}
	printf("%s: %d open, %d cleared, full %d\n", what, open, cleared,
	    full);
	ucl_object_unref(top);
}

static void
t_object(void)
{
	char	obj[256];

	memset(obj, 'a', 200);
	strcpy(obj + 200, "/delay");
	fault_set("tca", "Minor", obj, "probe", "over");
	fault_set("tca", "Minor", obj, "probe", "over again");
	count("set twice");
	fault_clear("tca", obj, "under");
	count("cleared");
	fault_set("tca", "Minor", obj, "probe", "over");
	count("set again");
}

static void
t_full(void)
{
	char	obj[32];
	int	i;

	quiet = true;
	for (i = 0; i < 2047; i++) {
		snprintf(obj, sizeof(obj), "t%d", i);
		fault_set("tunnel", "Major", obj, "probe", "down");
	}
	quiet = false;
	count("filled");
	fault_set("tunnel", "Major", "one-more", "probe", "down");
	fault_set("tunnel", "Major", "two-more", "probe", "down");
	count("two more");
	fault_clear("tunnel", "t0", "up");
	count("one cleared");
	quiet = true;
	fault_set("tunnel", "Major", "three-more", "probe", "down");
	quiet = false;
	count("one more");
	/* The oldest open one is still there. */
	printf("t1 %s\n", fault_update("tunnel", "t1", "still") ? "open" :
	    "gone");
}

static void
t_evict(void)
{
	char	obj[32];
	int	i;

	quiet = true;
	for (i = 0; i < 2048; i++) {
		snprintf(obj, sizeof(obj), "t%d", i);
		fault_set("tunnel", "Major", obj, "probe", "down");
		/* Every other one cleared, the first open. */
		if (i % 2 == 1)
			fault_clear("tunnel", obj, "up");
	}
	fault_set("tunnel", "Major", "new", "probe", "down");
	quiet = false;
	count("one more");
	printf("t0 %s\n", fault_update("tunnel", "t0", "still") ? "open" :
	    "gone");
	printf("new %s\n", fault_update("tunnel", "new", "still") ? "open" :
	    "gone");
}

static void
t_burst(void)
{
	struct timespec	ts = { 0, 100000000 };
	char		obj[32];
	int		i, w0;

	faults_start();
	quiet = true;
	w0 = writes;
	for (i = 0; i < 100; i++) {
		snprintf(obj, sizeof(obj), "t%d", i);
		fault_set("tunnel", "Major", obj, "probe", "down");
	}
	printf("written at once: %d\n", writes - w0);
	for (i = 0; i < 30 && writes == w0; i++)
		nanosleep(&ts, NULL);
	nanosleep(&ts, NULL);
	printf("written within 3 s: %s, %d time%s\n", writes > w0 ? "yes" :
	    "no", writes - w0, writes - w0 == 1 ? "" : "s");
	fault_clear("tunnel", "t0", "up");
	faults_save();
	printf("at the stop: %s\n", kept != NULL && strstr(kept,
	    "\"cleared\":true") != NULL ? "the clearing written" :
	    "not written");
}

static void
t_control(const char *path)
{
	FILE	*fp;
	char	 buf[8192], why[256];
	size_t	 n;

	if ((fp = fopen(path, "re")) == NULL)
		err(1, "%s", path);
	n = fread(buf, 1, sizeof(buf) - 1, fp);
	buf[n] = '\0';
	fclose(fp);
	why[0] = '\0';
	if (faults_control(buf, false, why, sizeof(why)) != 0)
		printf("refused: %s\n", why);
	else
		printf("taken\n");
}

static void
t_reconcile(void)
{
	struct fault_live	v[2];

	fault_set("tunnel", "Major", "a", "probe", "down");
	fault_set("tunnel", "Major", "b", "probe", "down");
	fault_set("tca", "Minor", "a/delay", "probe", "over");
	fault_set("tunnel", "Major", "x", "other", "down");
	memset(v, 0, sizeof(v));
	v[0].type = "tunnel";
	v[0].object = "a";
	v[1].type = "tca";
	v[1].object = "a/delay";
	printf("cleared %d\n", fault_reconcile("probe", NULL, NULL, v, 2,
	    "no longer measured"));
	printf("a %s, a/delay %s\n", v[0].open ? "open" : "not open",
	    v[1].open ? "open" : "not open");
	v[1].well = true;
	v[1].reason = "under the threshold";
	printf("cleared %d\n", fault_reconcile("probe", "tca", NULL, &v[1], 1,
	    "gone"));
	count("after");
}

static void
t_events(void)
{
	char	q[64];

	events_told(true);
	event_add("probe", "{\"id\":\"%s\"}", json_quote("a\"b\\c\td", q,
	    sizeof(q)));
	event_add("probe", "{\"id\":\"%s\"}", "a\"b");
	event_add("probe", "{\"id\":\"a\"}x");
	event_add("probe", "{\"n\":1.5e3,\"o\":{\"a\":[true,null,\"\\u00e9\"]}}");
}

int
main(int argc, char **argv)
{

	setvbuf(stdout, NULL, _IOLBF, 0);
	if (argc < 2)
		errx(1, "what is tried?");
	if (strcmp(argv[1], "object") == 0)
		t_object();
	else if (strcmp(argv[1], "full") == 0)
		t_full();
	else if (strcmp(argv[1], "evict") == 0)
		t_evict();
	else if (strcmp(argv[1], "burst") == 0)
		t_burst();
	else if (strcmp(argv[1], "control") == 0 && argc == 3)
		t_control(argv[2]);
	else if (strcmp(argv[1], "reconcile") == 0)
		t_reconcile();
	else if (strcmp(argv[1], "events") == 0)
		t_events();
	else
		errx(1, "%s: not one the test tries", argv[1]);
	return (0);
}
