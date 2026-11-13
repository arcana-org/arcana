/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef TEXTFIT_H
#define	TEXTFIT_H

#include <stdbool.h>

/* textfit.c: text fit to be shown, or escaped (4 * strlen + 1 bytes). */
bool	 text_fit(const char *, bool);
char	*text_vis(char *, const char *, bool);

#endif
