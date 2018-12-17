// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2018, STMicroelectronics
 */

#include <arm.h>
#include <boot_api.h>
#include <kernel/generic_boot.h>
#include <kernel/interrupt.h>
#include <kernel/misc.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <sm/psci.h>
#include <trace.h>

/*
 * SMP boot support and access to the mailbox
 */
#define GIC_SEC_SGI_0		8

static vaddr_t bckreg_base(void)
{
	static void *va;

	if (!cpu_mmu_enabled())
		return BKP_REGS_BASE + BKP_REGISTER_OFF;

	if (!va)
		va = phys_to_virt(BKP_REGS_BASE + BKP_REGISTER_OFF,
				  MEM_AREA_IO_SEC);

	return (vaddr_t)va;
}

static uint32_t *bckreg_address(unsigned int idx)
{
	return (uint32_t *)bckreg_base() + idx;
}

static void release_secondary_early_hpen(size_t __unused pos)
{
	uint32_t *p_entry = bckreg_address(BCKR_CORE1_BRANCH_ADDRESS);
	uint32_t *p_magic = bckreg_address(BCKR_CORE1_MAGIC_NUMBER);

	*p_entry = TEE_LOAD_ADDR;
	*p_magic = BOOT_API_A7_CORE1_MAGIC_NUMBER;

	dmb();
	isb();
	itr_raise_sgi(GIC_SEC_SGI_0, BIT(pos));
}

/* Override default psci_cpu_on() with platform specific sequence */
int psci_cpu_on(uint32_t core_id, uint32_t entry, uint32_t context_id)
{
	size_t pos = get_core_pos_mpidr(core_id);
	static bool core_is_released[CFG_TEE_CORE_NB_CORE];

	if (!pos || pos >= CFG_TEE_CORE_NB_CORE)
		return PSCI_RET_INVALID_PARAMETERS;

	DMSG("core pos: %zu: ns_entry %#" PRIx32, pos, entry);

	if (core_is_released[pos]) {
		DMSG("core %zu already released", pos);
		return PSCI_RET_DENIED;
	}
	core_is_released[pos] = true;

	generic_boot_set_core_ns_entry(pos, entry, context_id);
	release_secondary_early_hpen(pos);
}

/* Override default psci_cpu_on() with platform supported features */
int psci_features(uint32_t psci_fid)
{
	switch (psci_fid) {
	case PSCI_PSCI_FEATURES:
	case PSCI_VERSION:
#if CFG_TEE_CORE_NB_CORE > 1
	case PSCI_CPU_ON:
#endif
		return PSCI_RET_SUCCESS;
	default:
		return PSCI_RET_NOT_SUPPORTED;
	}
}

/* Override default psci_version() to enable PSCI_VERSION_1_0 API */
uint32_t psci_version(void)
{
	return PSCI_VERSION_1_0;
}
