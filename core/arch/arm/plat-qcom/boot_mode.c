// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <io.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <util.h>

#include "boot_mode.h"

#define TCSR_BOOT_MISC_DLOAD	BIT(4)

register_phys_mem_pgdir(MEM_AREA_IO_SEC, TCSR_BOOT_MISC_DETECT,
			sizeof(uint32_t));

TEE_Result qcom_is_dload_mode(bool *enabled)
{
	static vaddr_t boot_misc;

	if (!enabled)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!boot_misc) {
		boot_misc = (vaddr_t)phys_to_virt(TCSR_BOOT_MISC_DETECT,
						  MEM_AREA_IO_SEC,
						  sizeof(uint32_t));
		if (!boot_misc)
			return TEE_ERROR_GENERIC;
	}

	*enabled = io_read32(boot_misc) & TCSR_BOOT_MISC_DLOAD;

	return TEE_SUCCESS;
}
