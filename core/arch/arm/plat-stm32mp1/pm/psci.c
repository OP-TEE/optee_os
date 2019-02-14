// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2018, STMicroelectronics
 */

#include <arm.h>
#include <boot_api.h>
#include <drivers/stm32mp1_rcc.h>
#include <io.h>
#include <kernel/cache_helpers.h>
#include <kernel/delay.h>
#include <kernel/generic_boot.h>
#include <kernel/interrupt.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/spinlock.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <sm/psci.h>
#include <stm32_util.h>
#include <trace.h>

/*
 * SMP boot support and access to the mailbox
 */

enum core_state_id {
	CORE_OFF = 0,
	CORE_RET,
	CORE_AWAKE,
	CORE_ON,
};

static enum core_state_id core_state[CFG_TEE_CORE_NB_CORE];
static unsigned int __maybe_unused state_lock = SPINLOCK_UNLOCK;

static uint32_t __maybe_unused lock_state_access(void)
{
	return may_spin_lock(&state_lock);
}

static void __maybe_unused unlock_state_access(uint32_t exceptions)
{
	may_spin_unlock(&state_lock, exceptions);
}

int psci_affinity_info(uint32_t affinity, uint32_t lowest_affinity_level)
{
	unsigned int pos = get_core_pos_mpidr(affinity);

	DMSG("core %zu, state %u", pos, core_state[pos]);

	if ((pos >= CFG_TEE_CORE_NB_CORE) ||
	    (lowest_affinity_level > PSCI_AFFINITY_LEVEL_ON)) {
		return PSCI_RET_INVALID_PARAMETERS;
	}

	switch (core_state[pos]) {
	case CORE_OFF:
	case CORE_RET:
		return PSCI_AFFINITY_LEVEL_OFF;
	case CORE_AWAKE:
		return PSCI_AFFINITY_LEVEL_ON_PENDING;
	case CORE_ON:
		return PSCI_AFFINITY_LEVEL_ON;
	default:
		panic();
	}
}

#if CFG_TEE_CORE_NB_CORE == 1
/*
 * Function called when a CPU is booted through the OP-TEE.
 * All cores shall register when online.
 */
void stm32mp_register_online_cpu(void)
{
	assert(core_state[0] == CORE_OFF);
	core_state[0] = CORE_ON;
}
#else
static void __noreturn stm32_pm_cpu_power_down_wfi(void)
{
	dcache_op_level1(DCACHE_OP_CLEAN);

	io_write32(stm32_rcc_base() + RCC_MP_GRSTCSETR,
		   RCC_MP_GRSTCSETR_MPUP1RST);

	dsb();
	isb();
	wfi();
	panic();
}

void stm32mp_register_online_cpu(void)
{
	size_t pos = get_core_pos();
	uint32_t excep = lock_state_access();

	if (pos == 0) {
		assert(core_state[pos] == CORE_OFF);
	} else {
		if (core_state[pos] != CORE_AWAKE) {
			core_state[pos] = CORE_OFF;
			unlock_state_access(excep);
			stm32_pm_cpu_power_down_wfi();
			panic();
		}
	}

	core_state[pos] = CORE_ON;
	unlock_state_access(excep);
}

#define GICD_SGIR		0xF00
static void raise_sgi0_as_secure(void)
{
	dsb_ishst();
	io_write32(get_gicd_base() + GICD_SGIR,
		   GIC_NON_SEC_SGI_0 | SHIFT_U32(TARGET_CPU1_GIC_MASK, 16));
}

static void release_secondary_early_hpen(size_t __unused pos)
{
	/* Need to send SIG#0 over Group0 after individual core 1 reset */
	raise_sgi0_as_secure();
	udelay(20);

	io_write32(stm32mp_bkpreg(BCKR_CORE1_BRANCH_ADDRESS),
		   TEE_LOAD_ADDR);
	io_write32(stm32mp_bkpreg(BCKR_CORE1_MAGIC_NUMBER),
		   BOOT_API_A7_CORE1_MAGIC_NUMBER);

	dsb_ishst();
	itr_raise_sgi(GIC_SEC_SGI_0, TARGET_CPU1_GIC_MASK);
}

/* Override default psci_cpu_on() with platform specific sequence */
int psci_cpu_on(uint32_t core_id, uint32_t entry, uint32_t context_id)
{
	size_t pos = get_core_pos_mpidr(core_id);
	uint32_t excep;
	int rc;

	if (!pos || pos >= CFG_TEE_CORE_NB_CORE)
		return PSCI_RET_INVALID_PARAMETERS;

	DMSG("core %zu, ns_entry 0x%" PRIx32 ", state %u",
		pos, entry, core_state[pos]);

	excep = lock_state_access();

	switch (core_state[pos]) {
	case CORE_ON:
		rc = PSCI_RET_ALREADY_ON;
		break;
	case CORE_AWAKE:
		rc = PSCI_RET_ON_PENDING;
		break;
	case CORE_RET:
		rc = PSCI_RET_DENIED;
		break;
	case CORE_OFF:
		core_state[pos] = CORE_AWAKE;
		rc = PSCI_RET_SUCCESS;
		break;
	default:
		panic();
	}

	unlock_state_access(excep);

	if (rc == PSCI_RET_SUCCESS) {
		generic_boot_set_core_ns_entry(pos, entry, context_id);
		release_secondary_early_hpen(pos);
	}

	return rc;
}

/* Override default psci_cpu_off() with platform specific sequence */
int psci_cpu_off(void)
{
	unsigned int pos = get_core_pos();
	uint32_t excep;

	if (pos == 0) {
		EMSG("PSCI_CPU_OFF not supported for core #0");
		return PSCI_RET_INTERNAL_FAILURE;
	}

	DMSG("core %u", pos);

	excep = lock_state_access();

	assert(core_state[pos] == CORE_ON);
	core_state[pos] = CORE_OFF;

	unlock_state_access(excep);

	thread_mask_exceptions(THREAD_EXCP_ALL);
	stm32_pm_cpu_power_down_wfi();
	panic();
}
#endif

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
