// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022 Microsoft
 *
 * Driver for the Broadcom BNXT Nitro hot patch driver.
 */

#include <drivers/bcm/bnxt_nitro_hot_patch.h>

static vaddr_t staging_addr;
static uint32_t staging_size;
static uint32_t space_assigned;

TEE_Result nitro_hot_patch_init(paddr_t addr, uint32_t size)
{
	if (!size) {
		EMSG("Nitro hot patch init given memory size of 0x0");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	space_assigned = 0;
	staging_addr = (vaddr_t)phys_to_virt(addr, MEM_AREA_RAM_SEC, 1);
	if (!staging_addr) {
		EMSG("Couldn't translate address: %"PRIxPA, addr);
		staging_size = 0;
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	staging_size = size;

	return TEE_SUCCESS;
}

TEE_Result nitro_hot_patch_deinit(void)
{
	staging_addr = NULL;

	return TEE_SUCCESS;
}

TEE_Result update_nitro_hot_patch(void *buffer, uint32_t size)
{
	uint32_t new_total_patch_size = space_assigned;

	if (!staging_addr) {
		EMSG("Nitro hot patch driver not initialized");
		return TEE_ERROR_BAD_STATE;
	}
	if (!buffer) {
		EMSG("Nitro hot patch source buffer not valid");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	if (!size) {
		EMSG("Given nitro hot patch size of 0x0");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	new_total_patch_size += size;
	if (new_total_patch_size > staging_size) {
		EMSG("New total memory size will be larger than staging size");
		return TEE_ERROR_SHORT_BUFFER;
	}

	space_assigned = new_total_patch_size;

	memcpy((void *)(staging_addr + space_assigned), buffer, size);

	return TEE_SUCCESS;
}

TEE_Result verify_nitro_hot_patch(vaddr_t *staging_mem)
{
	if (staging_addr) {
		EMSG("Nitro hot patch driver not initialized");
		return TEE_ERROR_BAD_STATE;
	}

	if (!space_assigned) {
		EMSG("No data stored in staging memory");
		return TEE_ERROR_GENERIC;
	}

	staging_mem = staging_addr;

	return TEE_SUCCESS;
}
