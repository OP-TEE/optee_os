/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015-2016, Linaro Limited
 */
#ifndef CORE_MMU_PRIVATE_H
#define CORE_MMU_PRIVATE_H

#include <mm/core_mmu.h>
#include <mm/tee_mmu_types.h>


void core_init_mmu_tables(struct tee_mmap_region *mm);

void core_mmu_set_info_table(struct core_mmu_table_info *tbl_info,
			     unsigned level, vaddr_t va_base, void *table);
void core_mmu_populate_user_map(struct core_mmu_table_info *dir_info,
				struct user_ta_ctx *utc);

static inline bool core_mmap_is_end_of_table(const struct tee_mmap_region *mm)
{
	return mm->type == MEM_AREA_END;
}

#endif /*CORE_MMU_PRIVATE_H*/

