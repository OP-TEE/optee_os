/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017, Linaro Limited
 */

#ifndef __KERNEL_CACHE_HELPERS_ARCH_H
#define __KERNEL_CACHE_HELPERS_ARCH_H

#ifndef __ASSEMBLER__
#include <arm.h>
#include <types_ext.h>
#endif

#ifndef __ASSEMBLER__

static inline unsigned int dcache_get_line_size(void)
{
	uint32_t value = read_ctr();

	return CTR_WORD_SIZE <<
		((value >> CTR_DMINLINE_SHIFT) & CTR_DMINLINE_MASK);
}

#endif /*!__ASSEMBLER__*/

#endif /*__KERNEL_CACHE_HELPERS_ARCH_H*/
