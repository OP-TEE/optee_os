/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, RISCStar Solutions Corporation
 */

#ifndef __RISCV_PMP_H
#define __RISCV_PMP_H

#include <compiler.h>
#include <stdbool.h>
#include <stdint.h>
#include <types_ext.h>
#include <util.h>

/* Access bits of an opensbi,domain,memregion node, shifted down to bit 0 */
#define RISCV_PMP_R	BIT(0)
#define RISCV_PMP_W	BIT(1)
#define RISCV_PMP_X	BIT(2)

/* The core regions, in the order riscv_pmp_core_regions() describes them */
enum riscv_pmp_core_region {
	RISCV_PMP_CORE_REGION_TEXT,
	RISCV_PMP_CORE_REGION_RODATA,
	RISCV_PMP_CORE_REGION_RWDATA,
	RISCV_PMP_CORE_REGION_COUNT,
};

/*
 * struct riscv_pmp_region - a naturally aligned power-of-two memory region
 * @base:	physical base address, aligned to the region size
 * @va:		virtual address the core reaches the region through
 * @order:	log2 of the region size, the order a NAPOT PMP entry encodes
 * @perms:	RISCV_PMP_* access the region grants to S and U mode
 * @name:	region name, used when reporting the layout
 */
struct riscv_pmp_region {
	paddr_t base;
	vaddr_t va;
	uint8_t order;
	uint8_t perms;
	const char *name;
};

static inline size_t riscv_pmp_region_size(const struct riscv_pmp_region *r)
{
	return BIT64(r->order);
}

static inline bool riscv_pmp_region_is_napot(const struct riscv_pmp_region *r)
{
	return r->order >= 3 && IS_ALIGNED(r->base, BIT64(r->order));
}

#ifdef CFG_RISCV_CORE_NAPOT_REGIONS
/*
 * riscv_pmp_core_regions() - describe the core regions laid out by kern.ld.S
 * @regions:	caller allocated array, filled with at most @count entries.
 *		The names point at string literals and are never freed.
 * @count:	number of entries @regions has room for
 *
 * Returns the number of core regions, which is the number written to
 * @regions when @count is large enough and nothing otherwise, so that
 * passing (NULL, 0) asks how large @regions has to be.
 */
size_t riscv_pmp_core_regions(struct riscv_pmp_region *regions, size_t count);

/* Reports the core regions in the form the domain device tree takes */
void riscv_pmp_dump_core_regions(void);
#else
static inline size_t riscv_pmp_core_regions(struct riscv_pmp_region *r __unused,
					    size_t count __unused)
{
	return 0;
}

static inline void riscv_pmp_dump_core_regions(void)
{
}
#endif /*CFG_RISCV_CORE_NAPOT_REGIONS*/

#endif /*__RISCV_PMP_H*/
