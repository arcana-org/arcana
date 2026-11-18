/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef _ZPROG_H_
#define	_ZPROG_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * An arcana-agent as agent-update carries it compressed: gzip (RFC
 * 1952), by the base system's zlib.  The agent, the console and
 * arcanactl build the same file.
 */

/*
 * What arcana-host's agent feature names for it.  An agent without it
 * is sent no update and asked for no build: it is updated by hand.
 */
#define	ZPROG_FEATURE	"gzip-update"
#define	ZPROG_TOO_OLD(what)	"this host's arcana-agent is too old for " \
				what " by the console: update it by hand " \
				"(arcana-agent's port or the package)"

/*
 * The feature of an agent whose update's signature is of the update's
 * statement, not of the program: what the console signs and the agent
 * verifies, rebuilt by the agent from what it was sent and what it is.
 * The host it is for (its hostname, gethostname(3), as hello says it:
 * a statement for one host is refused by another), the version and
 * the program's SHA-256 (lower-case hex), and whether it may replace a
 * newer agent (downgrade yes or no: the intent signed, not a flag that
 * travels beside).  Sent to an agent without the feature, the console
 * signs the program alone: the one compatibility the update path keeps,
 * so that a console of 0.433.0 updates the agents before it; it goes
 * when no deployed agent predates 0.284.0 (docs/TODO.md).
 */
#define	SIGNED_UPDATE_FEATURE	"signed-update"
#define	UPDATE_STATEMENT	"arcana-agent update\nhost %s\nversion %s\n" \
				"sha256 %s\ndowngrade %s\n"

/*
 * The most bytes of compressed program an update carries: an agent's
 * frame is 8 MiB, the rest of the request well within the 64 KiB left.
 * The most it inflates to.
 */
#define	ZPROG_MAX_BINARY	(8 * 1024 * 1024 - 64 * 1024)
#define	ZPROG_MAX_PROGRAM	(32 * 1024 * 1024)

/* Whether the n features of a host's agent have ZPROG_FEATURE. */
bool		 zprog_taken(const char *const *v, size_t n);

/* len bytes of in compressed into *outp (malloc(3)): 0, or an errno. */
int		 zprog_deflate(const void *in, size_t len, uint8_t **outp,
		    size_t *outlenp);

/*
 * len bytes of in inflated into *outp (malloc(3)), which has to come
 * to size bytes, no more than max: NULL, or why not.  It stops a byte
 * past size.
 */
const char	*zprog_inflate(const void *in, size_t len, size_t size,
		    size_t max, uint8_t **outp);

#endif /* !_ZPROG_H_ */
