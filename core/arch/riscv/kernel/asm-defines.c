// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022 NXP
 */

#include <gen-asm-defines.h>
#include <kernel/boot.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <types_ext.h>

DEFINES
{
	/* struct core_mmu_config */
	DEFINE(CORE_MMU_CONFIG_SIZE, sizeof(struct core_mmu_config));
	DEFINE(CORE_MMU_CONFIG_LOAD_OFFSET,
	       offsetof(struct core_mmu_config, load_offset));
	DEFINE(CORE_MMU_CONFIG_SATP,
	       offsetof(struct core_mmu_config, satp));
}
