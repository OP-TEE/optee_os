// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Advanced Micro Devices, Inc. All rights reserved.
 *
 */

#include <drivers/amd/asu_fw_info.h>
#include <io.h>
#include <mm/core_mmu.h>
#include <trace.h>

/*
 * Covers the RTCA offsets read through this file: the module info array
 * (ASU_RTCA_MODULE_INFO_OFFSET onward, ASU_RTCA_MODULE_COUNT entries) and
 * the FW version register (ASU_RTCA_FW_VERSION_OFFSET).
 */
#define ASU_RTCA_FW_INFO_MAP_SIZE	0x200U

/*
 * Cached mapping for the RTCA FW-info region. Created once and never
 * unmapped - core_mmu_remove_mapping() would also tear down asu_main.c's
 * shared channel-memory mapping in the same translation block, causing a
 * data abort on the next ASU queue access.
 */
static void *asu_rtca_fw_info_base;

/*
 * asu_rtca_map() - Return the (persistent) mapping for the RTCA region
 * used for FW info
 *
 * Return: Mapped base address, or NULL on failure
 */
static void *asu_rtca_map(void)
{
	if (!asu_rtca_fw_info_base) {
		asu_rtca_fw_info_base =
			core_mmu_add_mapping(MEM_AREA_IO_SEC,
					     ASU_RTCA_BASEADDR,
					     ASU_RTCA_FW_INFO_MAP_SIZE);
		if (!asu_rtca_fw_info_base)
			EMSG("Failed to map RTCA for FW info");
	}

	return asu_rtca_fw_info_base;
}

TEE_Result asu_rtca_get_fw_version(uint8_t *major, uint8_t *minor)
{
	void *rtca = NULL;
	uint32_t val = 0;

	if (!major || !minor)
		return TEE_ERROR_BAD_PARAMETERS;

	rtca = asu_rtca_map();
	if (!rtca)
		return TEE_ERROR_GENERIC;

	val = io_read32((vaddr_t)rtca + ASU_RTCA_FW_VERSION_OFFSET);

	*major = (val & ASU_FW_VERSION_MAJOR_MASK) >>
		 ASU_FW_VERSION_MAJOR_SHIFT;
	*minor = val & ASU_FW_VERSION_MINOR_MASK;

	return TEE_SUCCESS;
}

TEE_Result asu_rtca_get_module_info(uint32_t module_id,
				    struct asu_crypto_alg_info *info)
{
	void *rtca = NULL;
	vaddr_t entry = 0;

	if (!info || module_id >= ASU_RTCA_MODULE_COUNT)
		return TEE_ERROR_BAD_PARAMETERS;

	rtca = asu_rtca_map();
	if (!rtca)
		return TEE_ERROR_GENERIC;

	entry = (vaddr_t)rtca + ASU_RTCA_MODULE_INFO_OFFSET +
		module_id * ASU_RTCA_MODULE_INFO_STRIDE;

	info->version = io_read32(entry);
	info->nist_status = io_read8(entry + 4);
	info->kat_status = io_read8(entry + 5);
	info->feature_caps = io_read16(entry + 6);
	info->reserved4 = io_read32(entry + 8);

	return TEE_SUCCESS;
}

bool asu_module_version_at_least(const struct fw_module_info *mod,
				 uint16_t min_major, uint16_t min_minor)
{
	uint16_t major = 0;
	uint16_t minor = 0;

	if (!mod || !mod->valid)
		return false;

	major = (mod->version & ASU_MODULE_VERSION_MAJOR_MASK) >>
		ASU_MODULE_VERSION_MAJOR_SHIFT;
	minor = mod->version & ASU_MODULE_VERSION_MINOR_MASK;

	return major > min_major ||
	       (major == min_major && minor >= min_minor);
}
