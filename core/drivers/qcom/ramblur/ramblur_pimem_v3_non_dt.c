// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/qcom/ramblur/v3/ramblur_pimem_hwio.h>
#include <initcall.h>
#include <kernel/panic.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include "ramblur_pimem_v3.h"

static TEE_Result ramblur_pimem_init(void)
{
	vaddr_t regs = 0;

	regs = (vaddr_t)core_mmu_add_mapping(MEM_AREA_IO_SEC,
					     RAMBLUR_PIMEM_REG_BASE,
					     RAMBLUR_PIMEM_REG_SIZE);
	if (!regs)
		panic("Can't map Ramblur pIMEM");

	return ramblur_pimem_v3_init(regs, RAMBLUR_PIMEM_VAULT_TA_BASE,
				     RAMBLUR_PIMEM_VAULT_TA_SIZE);
}
driver_init(ramblur_pimem_init);
