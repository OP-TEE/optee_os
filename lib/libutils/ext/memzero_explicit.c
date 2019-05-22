// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2019 Linaro Limited
 */

#include <string.h>
#include <string_ext.h>

/*
 * This method prevents dead store elimination, which could happen in case
 * link-time optimization (LTO) is used.
 * See "Dead Store Elimination (Still) Considered Harmful" [1] section 3.3.3.
 *
 * [1]
 * http://www.usenix.org/system/files/conference/usenixsecurity17/sec17-yang.pdf
 */
static volatile void * (*memset_func)(void *, int, size_t) =
	(volatile void * (*)(void *, int, size_t))&memset;

void memzero_explicit(void *s, size_t count)
{
	memset_func(s, 0, count);
}
