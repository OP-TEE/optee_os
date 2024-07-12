// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024, STMicroelectronics
 */

#include <stdlib.h>
#include <util.h>

#define QSORT_HELPER(name, type)				\
static int cmp_ ## name(const void *a, const void *b)		\
{								\
	const type *ia = a;					\
	const type *ib = b;					\
								\
	return CMP_TRILEAN(*ia, *ib);				\
}								\
								\
void qsort_ ## name(type *aa, size_t n)				\
{								\
	qsort(aa, n, sizeof(*aa), cmp_ ## name);		\
}

QSORT_HELPER(int, int);
QSORT_HELPER(uint, unsigned int);
QSORT_HELPER(long, long int);
QSORT_HELPER(ul, unsigned long int);
QSORT_HELPER(ll, long long int);
QSORT_HELPER(ull, unsigned long long int);
QSORT_HELPER(s8, int8_t);
QSORT_HELPER(u8, uint8_t);
QSORT_HELPER(s16, int16_t);
QSORT_HELPER(u16, uint16_t);
QSORT_HELPER(s32, int32_t);
QSORT_HELPER(u32, uint32_t);
QSORT_HELPER(s64, int64_t);
QSORT_HELPER(u64, uint64_t);
