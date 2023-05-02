/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

/*
 * This file provides what C99 standard requires for <stdlib.h> in
 * 7.20.3 Memory management functions
 */

#ifndef __STDLIB_H
#define __STDLIB_H

#include <compiler.h>
#include <stddef.h>
#include <malloc.h>

void
qsort(void *aa, size_t n, size_t es, int (*cmp)(const void *, const void *));

void abort(void) __noreturn;

int abs(int i);

/* The largest number returned by rand() */
#define	RAND_MAX	__INT_MAX__
int rand(void);

unsigned long _strtoul (const char *nptr, char **endptr, int base);
unsigned long strtoul (const char *s, char **ptr, int base);

#endif /* __STDLIB_H */
