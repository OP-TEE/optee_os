/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015-2016, Linaro Limited
 */
#ifndef CORE_MMU_PRIVATE_H
#define CORE_MMU_PRIVATE_H

#include <mm/core_mmu.h>
#include <mm/tee_mmu_types.h>


void core_init_mmu(struct tee_mmap_region *mm);

void core_mmu_set_info_table(struct core_mmu_table_info *tbl_info,
			     unsigned level, vaddr_t va_base, void *table);
void core_mmu_populate_user_map(struct core_mmu_table_info *dir_info,
				struct user_mode_ctx *uctx);
void core_mmu_map_region(struct mmu_partition *prtn,
			 struct tee_mmap_region *mm);

static inline bool core_mmap_is_end_of_table(const struct tee_mmap_region *mm)
{
	return mm->type == MEM_AREA_END;
}

static inline bool core_mmu_check_max_pa(paddr_t pa __maybe_unused)
{
#if defined(ARM64)
	return pa <= (BIT64(CFG_CORE_ARM64_PA_BITS) - 1);
#elif defined(CFG_CORE_LARGE_PHYS_ADDR)
	return pa <= (BIT64(40) - 1);
#else
	COMPILE_TIME_ASSERT(sizeof(paddr_t) == sizeof(uint32_t));
	return true;
#endif
}

static inline bool core_mmu_check_end_pa(paddr_t pa, size_t len)
{
	paddr_t end_pa = 0;

	if (ADD_OVERFLOW(pa, len - 1, &end_pa))
		return false;
	return core_mmu_check_max_pa(end_pa);
}

#endif /*CORE_MMU_PRIVATE_H*/

