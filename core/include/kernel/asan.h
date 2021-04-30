/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, Linaro Limited
 */
#ifndef __KERNEL_ASAN_H
#define __KERNEL_ASAN_H

#include <stdint.h>

#define ASAN_DATA_RED_ZONE	-1
#define ASAN_HEAP_RED_ZONE	-2

#define ASAN_BLOCK_SIZE		U(8)
#define ASAN_BLOCK_SHIFT	U(3)
#define ASAN_BLOCK_MASK		(ASAN_BLOCK_SIZE - 1)

#ifndef __ASSEMBLER__
#include <string.h>
#include <types_ext.h>

void asan_set_shadowed(const void *va_begin, const void *va_end);
void asan_start(void);

#ifdef CFG_CORE_SANITIZE_KADDRESS
void asan_tag_no_access(const void *begin, const void *end);
void asan_tag_access(const void *begin, const void *end);
void asan_tag_heap_free(const void *begin, const void *end);
void *asan_memset_unchecked(void *s, int c, size_t n);
void *asan_memcpy_unchecked(void *__restrict s1, const void *__restrict s2,
			    size_t n);
#else
static inline void asan_tag_no_access(const void *begin __unused,
				      const void *end __unused)
{
}
static inline void asan_tag_access(const void *begin __unused,
				   const void *end __unused)
{
}
static inline void asan_tag_heap_free(const void *begin __unused,
				      const void *end __unused)
{
}

static inline void *asan_memset_unchecked(void *s, int c, size_t n)
{
	return memset(s, c, n);
}

static inline void *asan_memcpy_unchecked(void *__restrict s1,
					  const void *__restrict s2, size_t n)
{
	return memcpy(s1, s2, n);
}

#endif

#endif /*__ASSEMBLER__*/
#endif /*__KERNEL_ASAN_H*/
