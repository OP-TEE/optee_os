/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017, Linaro Limited
 */

#ifndef __KERNEL_CACHE_HELPERS_H
#define __KERNEL_CACHE_HELPERS_H

#ifndef __ASSEMBLER__
#include <kernel/cache_helpers_arch.h>
#include <types_ext.h>
#endif

/* Data Cache set/way op type defines */
#define DCACHE_OP_INV		0x0
#define DCACHE_OP_CLEAN_INV	0x1
#define DCACHE_OP_CLEAN		0x2

#ifndef __ASSEMBLER__
void dcache_cleaninv_range(void *addr, size_t size);
void dcache_clean_range(void *addr, size_t size);
void dcache_inv_range(void *addr, size_t size);
void dcache_clean_range_pou(void *addr, size_t size);

void icache_inv_all(void);
void icache_inv_range(void *addr, size_t size);
void icache_inv_user_range(void *addr, size_t size);

void dcache_op_louis(unsigned long op_type);
void dcache_op_all(unsigned long op_type);

void dcache_op_level1(unsigned long op_type);
void dcache_op_level2(unsigned long op_type);
void dcache_op_level3(unsigned long op_type);

/*
 * Get system maximum cache line size.
 */
static inline unsigned int cache_get_max_line_size(void)
{
	return 1 << CFG_MAX_CACHE_LINE_SHIFT;
}
#endif /*!__ASSEMBLER__*/

#endif /*__KERNEL_CACHE_HELPERS_H*/
