/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

/*
 * This file provides extensions for functions not defined in <string.h>
 */

#ifndef __STRING_EXT_H
#define __STRING_EXT_H

#include <stddef.h>
#include <sys/cdefs.h>

/*
 * Copy src to string dst of siz size.  At most siz-1 characters
 * will be copied.  Always NUL terminates (unless siz == 0).
 * Returns strlen(src); if retval >= siz, truncation occurred.
 */
size_t strlcpy(char *dst, const char *src, size_t size);
size_t strlcat(char *dst, const char *src, size_t size);

/* A constant-time version of memcmp() */
int consttime_memcmp(const void *p1, const void *p2, size_t nb);

/* Deprecated. For backward compatibility. */
static inline int buf_compare_ct(const void *s1, const void *s2, size_t n)
{
	return consttime_memcmp(s1, s2, n);
}

/* Variant of strdup() that uses nex_malloc() instead of malloc() */
char *nex_strdup(const char *s);

/*
 * Like memset(s, 0, count) but prevents the compiler from optimizing the call
 * away. Such "dead store elimination" optimizations typically occur when
 * clearing a *local* variable that is not used after it is cleared; but
 * link-time optimization (LTO) can also trigger code elimination in other
 * circumstances. See "Dead Store Elimination (Still) Considered Harmful" [1]
 * for details and examples (and note that the Cland compiler enables LTO by
 * default!).
 *
 * [1] https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-yang.pdf
 *
 * Practically speaking:
 *
 * - Use memzero_explicit() to *clear* (as opposed to initialize) *sensitive*
 *   data (such as keys, passwords, cryptographic state);
 * - Otherwise, use memset().
 */
void memzero_explicit(void *s, size_t count);

#endif /* __STRING_EXT_H */
