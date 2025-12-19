/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, Linaro Limited
 */
#ifndef __ASAN_H
#define __ASAN_H

#include <stdint.h>

#define ASAN_DATA_RED_ZONE	-1
#define ASAN_HEAP_RED_ZONE	-2

#define ASAN_BLOCK_SIZE		U(8)
#define ASAN_BLOCK_SHIFT	U(3)
#define ASAN_BLOCK_MASK		(ASAN_BLOCK_SIZE - 1)

#ifndef __ASSEMBLER__
#include <compiler.h>
#include <string.h>
#include <types_ext.h>

#define ASAN_VA_REGS_MAX 32

/* Represents memory mapped region */
struct asan_va_reg {
	vaddr_t lo;
	vaddr_t hi;
};

/* Global structure with ASan metadata */
struct asan_global_info {
	/* Virtual memory regions allowed for ASan checks */
	size_t regs_count;
	struct asan_va_reg regs[ASAN_VA_REGS_MAX];
	/* Shadow memory regions */
	size_t s_regs_count;
	struct asan_va_reg s_regs[ASAN_VA_REGS_MAX];
};

#ifdef __KERNEL__
#define GET_ASAN_INFO() (&__asan_global_info)
#else
#define GET_ASAN_INFO() ((struct asan_global_info *) \
	(CFG_USER_ASAN_SHADOW_OFFSET - SMALL_PAGE_SIZE))
#endif

#if ((defined(__KERNEL__) || defined(__LDELF__)) && defined(CFG_CORE_SANITIZE_KADDRESS))
#define IS_ASAN_ENABLED 1
#else
#define IS_ASAN_ENABLED 0
#endif

#if IS_ASAN_ENABLED == 1
/* ASAN enabled */
typedef void (*asan_panic_cb_t)(void);

void asan_set_shadowed(const void *va_begin, const void *va_end);
void asan_start(void);
void asan_panic(void);
void asan_set_panic_cb(asan_panic_cb_t panic_cb);

void asan_tag_no_access(const void *begin, const void *end);
void asan_tag_access(const void *begin, const void *end);
void asan_tag_heap_free(const void *begin, const void *end);
void *asan_memset_unchecked(void *s, int c, size_t n);
void *asan_memcpy_unchecked(void *__restrict s1, const void *__restrict s2,
			    size_t n);
int asan_user_map_shadow(void *lo, void *hi);
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

static inline void asan_start(void)
{
}

static inline int asan_user_map_shadow(void *lo __unused, void *hi __unused)
{
    return 0;
}
#endif /* IS_ASAN_ENABLED */

#endif /*__ASSEMBLER__*/
#endif /*__ASAN_H*/
