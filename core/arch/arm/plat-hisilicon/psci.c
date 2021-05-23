// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, HiSilicon Technologies Co., Ltd.
 */

#include <console.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>
#include <sm/optee_smc.h>
#include <sm/psci.h>
#include <sm/std_smc.h>
#include <tee/entry_std.h>
#include <tee/entry_fast.h>

#define REG_CPU_SUSSYS_RESET	0xcc
#define REG_CPU_START_COMMAND	0x0
#define REG_CPU_START_ADDR	0x4
#define REG_SYSCTRL_RESET	0x4
#define RELEASE_CORE_MASK	(BIT32(25) | BIT32(1))

int psci_features(uint32_t psci_fid)
{
	switch (psci_fid) {
	case ARM_SMCCC_VERSION:
	case PSCI_PSCI_FEATURES:
	case PSCI_VERSION:
	case PSCI_SYSTEM_RESET:
#ifdef CFG_BOOT_SECONDARY_REQUEST
	case PSCI_CPU_ON:
#endif
		return PSCI_RET_SUCCESS;
	default:
		return PSCI_RET_NOT_SUPPORTED;
	}
}

uint32_t psci_version(void)
{
	return PSCI_VERSION_1_0;
}

void psci_system_reset(void)
{
	vaddr_t sysctrl = core_mmu_get_va(SYS_CTRL_BASE, MEM_AREA_IO_SEC,
					  SYS_CTRL_SIZE);

	if (!sysctrl) {
		EMSG("no sysctrl mapping, hang here");
		panic();
	}

	io_write32(sysctrl + REG_SYSCTRL_RESET, 0xdeadbeef);
}

#ifdef CFG_BOOT_SECONDARY_REQUEST
int psci_cpu_on(uint32_t core_idx, uint32_t entry,
		uint32_t context_id)
{
	uint32_t val = 0;
	size_t pos = get_core_pos_mpidr(core_idx);
	vaddr_t bootsram = core_mmu_get_va(BOOTSRAM_BASE, MEM_AREA_IO_SEC,
					   BOOTSRAM_SIZE);
	vaddr_t crg = core_mmu_get_va(CPU_CRG_BASE, MEM_AREA_IO_SEC,
				      CPU_CRG_SIZE);

	if (!bootsram || !crg) {
		EMSG("No bootsram or crg mapping");
		return PSCI_RET_INVALID_PARAMETERS;
	}

	if ((pos == 0) || (pos >= CFG_TEE_CORE_NB_CORE))
		return PSCI_RET_INVALID_PARAMETERS;

	/* set secondary core's NS entry addresses */
	boot_set_core_ns_entry(pos, entry, context_id);

	val = virt_to_phys((void *)TEE_TEXT_VA_START);
	io_write32(bootsram + REG_CPU_START_ADDR, val);
	io_write32(bootsram + REG_CPU_START_COMMAND, 0xe51ff004);

	/* release secondary core */
	io_clrbits32(crg + REG_CPU_SUSSYS_RESET, RELEASE_CORE_MASK);

	return PSCI_RET_SUCCESS;
}
#endif
