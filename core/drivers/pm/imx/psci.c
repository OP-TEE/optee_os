// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2016 Freescale Semiconductor, Inc.
 * Copyright 2023 NXP
 *
 * Peng Fan <peng.fan@nxp.com>
 */

#include <drivers/imx_snvs.h>
#include <drivers/imx_wdog.h>
#include <io.h>
#include <imx.h>
#include <kernel/boot.h>
#include <kernel/misc.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <stdint.h>
#include <sm/psci.h>
#include <sm/std_smc.h>

#include "local.h"

#define IOMUXC_GPR5_OFFSET 0x14
#define ARM_WFI_STAT_MASK(n) BIT(n)

int psci_features(uint32_t psci_fid)
{
	switch (psci_fid) {
	case ARM_SMCCC_VERSION:
	case PSCI_PSCI_FEATURES:
	case PSCI_VERSION:
	case PSCI_CPU_OFF:
#ifdef CFG_BOOT_SECONDARY_REQUEST
	case PSCI_CPU_ON:
#endif
	case PSCI_AFFINITY_INFO:
	case PSCI_SYSTEM_OFF:
	case PSCI_SYSTEM_RESET:
	case PSCI_SYSTEM_RESET2:
		return PSCI_RET_SUCCESS;
	default:
		return PSCI_RET_NOT_SUPPORTED;
	}
}

uint32_t psci_version(void)
{
	return PSCI_VERSION_1_0;
}

#ifdef CFG_BOOT_SECONDARY_REQUEST
int psci_cpu_on(uint32_t core_idx, uint32_t entry, uint32_t context_id)
{
	if (core_idx == 0 || core_idx >= CFG_TEE_CORE_NB_CORE)
		return PSCI_RET_INVALID_PARAMETERS;

	/* set secondary cores' NS entry addresses */
	boot_set_core_ns_entry(core_idx, entry, context_id);
	imx_set_src_gpr_entry(core_idx, virt_to_phys((void *)TEE_LOAD_ADDR));

#ifdef CFG_MX7
	imx_gpcv2_set_core1_pup_by_software();
	imx_src_release_secondary_core(core_idx);
#else
	imx_src_release_secondary_core(core_idx);
	imx_set_src_gpr_arg(core_idx, 0);
#endif /* CFG_MX7 */

	IMSG("psci on ok");

	return PSCI_RET_SUCCESS;
}

int __noreturn psci_cpu_off(void)
{
	uint32_t core_id = get_core_pos();

	IMSG("core_id: %" PRIu32, core_id);

	psci_armv7_cpu_off();

	imx_set_src_gpr_arg(core_id, UINT32_MAX);

	thread_mask_exceptions(THREAD_EXCP_ALL);

	while (true)
		wfi();
}

int psci_affinity_info(uint32_t affinity,
		       uint32_t lowest_affnity_level __unused)
{
	vaddr_t base = core_mmu_get_va(IOMUXC_BASE, MEM_AREA_IO_SEC,
				       IOMUXC_SIZE);
	uint32_t cpu = affinity;
	bool wfi = true;

	if (!soc_is_imx7ds())
		wfi = io_read32(base + IOMUXC_GPR5_OFFSET) &
		      ARM_WFI_STAT_MASK(cpu);

	if (imx_get_src_gpr_arg(cpu) == 0 || !wfi)
		return PSCI_AFFINITY_LEVEL_ON;

	DMSG("cpu: %" PRIu32 "GPR: %" PRIx32, cpu, imx_get_src_gpr_arg(cpu));

	while (imx_get_src_gpr_arg(cpu) != UINT_MAX)
		;

	imx_src_shutdown_core(cpu);
	imx_set_src_gpr_arg(cpu, 0);

	return PSCI_AFFINITY_LEVEL_OFF;
}
#endif

void __noreturn psci_system_off(void)
{
#ifndef CFG_MX7ULP
	imx_snvs_shutdown();
#endif
	dsb();

	while (1)
		;
}

void __noreturn psci_system_reset(void)
{
	imx_wdog_restart(true);
}

int __noreturn psci_system_reset2(uint32_t reset_type __unused,
				  uint32_t cookie __unused)
{
	/* force WDOG reset */
	imx_wdog_restart(false);
}
