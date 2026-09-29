// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Advanced Micro Devices, Inc. All rights reserved.
 *
 */

#include <drivers/amd/pmc_fw_info.h>
#include <drivers/amd/pmc_sharedmem.h>
#include <initcall.h>
#include <inttypes.h>
#include <io.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <trace.h>
#include <util.h>

/* Large enough to cover PMC_RTCA_VERSION_OFFSET. */
#define PMC_RTCA_FW_INFO_MAP_SIZE	0x400U

TEE_Result pmc_rtca_get_version(uint8_t *major, uint8_t *minor)
{
	vaddr_t rtca = 0;
	uint32_t val = 0;

	if (!major || !minor)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * Same block as PLAT_SST_BASE, kept statically mapped by main.c; no
	 * dynamic map/unmap here so as not to tear down that shared mapping.
	 */
	rtca = (vaddr_t)phys_to_virt(PMC_RTCA_BASEADDR, MEM_AREA_IO_SEC,
				     PMC_RTCA_FW_INFO_MAP_SIZE);
	if (!rtca) {
		EMSG("RTCA not mapped for PMC FW info");
		return TEE_ERROR_GENERIC;
	}

	val = io_read32(rtca + PMC_RTCA_VERSION_OFFSET);

	*major = (val & PMC_VERSION_MAJOR_MASK) >> PMC_VERSION_MAJOR_SHIFT;
	*minor = (val & PMC_VERSION_MINOR_MASK) >> PMC_VERSION_MINOR_SHIFT;

	return TEE_SUCCESS;
}

void pmc_fw_compat_check(void)
{
	uint8_t major = 0;
	uint8_t minor = 0;
	uint32_t version = 0;
	uint32_t min_version = 0;

	if (pmc_rtca_get_version(&major, &minor) != TEE_SUCCESS) {
		EMSG("Failed to read PLM version from RTCA");
		panic("Incompatible PLM version");
	}

	IMSG("PLM version: %"PRIu8".%"PRIu8, major, minor);

	/* Packed compare avoids -Wtype-limits; see asu_fw_compat_probe(). */
	version = SHIFT_U32(major, 8) | minor;
	min_version = SHIFT_U32(CFG_AMD_PMC_MINVER_MAJ, 8) |
		      CFG_AMD_PMC_MINVER_MNR;

	if (version < min_version) {
		EMSG("PLM version %"PRIu8".%"PRIu8" older than minimum %u.%u",
		     major, minor, CFG_AMD_PMC_MINVER_MAJ,
		     CFG_AMD_PMC_MINVER_MNR);
		panic("Incompatible PLM version");
	}
}

static TEE_Result pmc_fw_compat_probe(void)
{
	pmc_fw_compat_check();

	return TEE_SUCCESS;
}

service_init(pmc_fw_compat_probe);
