/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022,2026 NXP
 */

#ifndef __KERNEL_CACHE_HELPERS_ARCH_H
#define __KERNEL_CACHE_HELPERS_ARCH_H

#ifndef __ASSEMBLER__
#include <kernel/hart.h>
#include <types_ext.h>
#include <util.h>
#endif

#ifndef __ASSEMBLER__

/*
 * Size of a data cache block, the unit the Zicbom operations work on. The
 * device tree gives it in the CPU nodes; without it the build-time
 * maximum is all the port knows.
 */
static inline unsigned int dcache_get_line_size(void)
{
	unsigned int size = riscv_cbom_block_size();

	if (!size)
		size = BIT32(CFG_MAX_CACHE_LINE_SHIFT);

	return size;
}

#endif /*!__ASSEMBLER__*/

#endif /*__KERNEL_CACHE_HELPERS_ARCH_H*/
