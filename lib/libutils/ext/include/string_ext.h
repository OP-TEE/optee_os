/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

/*
 * This file provides extensions for functions not defined in <string.h>
 */

#ifndef STRING_EXT_H
#define STRING_EXT_H

#include <stddef.h>
#include <sys/cdefs.h>

/*
 * Copy src to string dst of siz size.  At most siz-1 characters
 * will be copied.  Always NUL terminates (unless siz == 0).
 * Returns strlen(src); if retval >= siz, truncation occurred.
 */
size_t strlcpy(char *dst, const char *src, size_t size);
size_t strlcat(char *dst, const char *src, size_t size);

/*
 * This memory compare function will compare two buffers in a constant time.
 *
 * Note that this function will not have same kind of return values as the
 * traditional libc memcmp which return either less than or greater than zero
 * depending on which string that is lexically greater. This function will
 * return 0 if it is a match, otherwise it will return a non-zero value.
 */
int buf_compare_ct(const void *s1, const void *s2, size_t n);

#endif /* STRING_EXT_H */
