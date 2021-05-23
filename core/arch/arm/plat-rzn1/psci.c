// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017, Schneider Electric
 * Copyright (c) 2020, Linaro Limited
 */

#include <arm.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/misc.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <sm/psci.h>
#include <sm/std_smc.h>

#define SYSCTRL_REG_RSTEN		(SYSCTRL_BASE + 0x120)
#define SYSCTRL_REG_RSTCTRL		(SYSCTRL_BASE + 0x198)
#define SYSCTRL_BOOTADDR_REG		(SYSCTRL_BASE + 0x204)

#define SYSCTRL_REG_RSTEN_MRESET_EN	BIT(0)
#define SYSCTRL_REG_RSTEN_SWRST_EN	BIT(6)
#define SYSCTRL_REG_RSTCTRL_SWRST_REQ	BIT(6)

int psci_features(uint32_t psci_fid)
{
	switch (psci_fid) {
	case PSCI_PSCI_FEATURES:
	case PSCI_VERSION:
	case PSCI_CPU_ON:
	case PSCI_CPU_OFF:
	case PSCI_SYSTEM_RESET:
		return PSCI_RET_SUCCESS;
	default:
		return PSCI_RET_NOT_SUPPORTED;
	}
}

uint32_t psci_version(void)
{
	return PSCI_VERSION_1_0;
}

int psci_cpu_on(uint32_t core_id, uint32_t entry, uint32_t context_id)
{
	vaddr_t sctl_va = core_mmu_get_va(SYSCTRL_BOOTADDR_REG,
					  MEM_AREA_IO_SEC,
					  sizeof(uint32_t));

	if (core_id == 0 || core_id >= CFG_TEE_CORE_NB_CORE)
		return PSCI_RET_INVALID_PARAMETERS;

	DMSG("core_id: %" PRIu32, core_id);

	boot_set_core_ns_entry(core_id, entry, context_id);
	io_write32(sctl_va, TEE_LOAD_ADDR);

	dsb();
	sev();

	return PSCI_RET_SUCCESS;
}

int __noreturn psci_cpu_off(void)
{
	DMSG("core_id: %" PRIu32, get_core_pos());

	psci_armv7_cpu_off();

	thread_mask_exceptions(THREAD_EXCP_ALL);

	while (1)
		wfi();
}

void psci_system_reset(void)
{
	/* Enable software reset */
	io_setbits32(core_mmu_get_va(SYSCTRL_REG_RSTEN, MEM_AREA_IO_SEC,
				     sizeof(uint32_t)),
		     SYSCTRL_REG_RSTEN_SWRST_EN | SYSCTRL_REG_RSTEN_MRESET_EN);

	/* Trigger software reset */
	io_setbits32(core_mmu_get_va(SYSCTRL_REG_RSTCTRL, MEM_AREA_IO_SEC,
				     sizeof(uint32_t)),
		     SYSCTRL_REG_RSTCTRL_SWRST_REQ);

	dsb();
}
