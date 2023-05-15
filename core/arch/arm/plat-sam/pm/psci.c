// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, Microchip
 */

#include <drivers/atmel_rstc.h>
#include <drivers/atmel_shdwc.h>
#include <drivers/pm/sam/atmel_pm.h>
#include <kernel/panic.h>
#include <sm/psci.h>
#include <sm/std_smc.h>
#include <stdint.h>
#include <trace.h>

int psci_system_suspend(uintptr_t entry, uint32_t context_id __unused,
			struct sm_nsec_ctx *nsec)
{
	if (!atmel_pm_suspend_available())
		return PSCI_RET_NOT_SUPPORTED;

	if (atmel_pm_suspend(entry, nsec))
		return PSCI_RET_INTERNAL_FAILURE;

	return PSCI_RET_SUCCESS;
}

int psci_cpu_suspend(uint32_t power_state,
		     uintptr_t entry __unused, uint32_t context_id __unused,
		     struct sm_nsec_ctx *nsec __unused)
{
	uint32_t type = 0;

	if (atmel_pm_suspend_available())
		return PSCI_RET_NOT_SUPPORTED;

	type = (power_state & PSCI_POWER_STATE_TYPE_MASK) >>
		PSCI_POWER_STATE_TYPE_SHIFT;

	if (type != PSCI_POWER_STATE_TYPE_STANDBY) {
		DMSG("Power state %x not supported", type);
		return PSCI_RET_INVALID_PARAMETERS;
	}

	atmel_pm_cpu_idle();

	return PSCI_RET_SUCCESS;
}

void __noreturn psci_system_off(void)
{
	if (!atmel_shdwc_available())
		panic();

	atmel_shdwc_shutdown();
}

void __noreturn psci_system_reset(void)
{
	if (!atmel_rstc_available())
		panic();

	atmel_rstc_reset();
}

int psci_features(uint32_t psci_fid)
{
	switch (psci_fid) {
	case ARM_SMCCC_VERSION:
	case PSCI_PSCI_FEATURES:
	case PSCI_VERSION:
		return PSCI_RET_SUCCESS;
	case PSCI_SYSTEM_RESET:
		if (atmel_rstc_available())
			return PSCI_RET_SUCCESS;
		return PSCI_RET_NOT_SUPPORTED;
	case PSCI_SYSTEM_OFF:
		if (atmel_shdwc_available())
			return PSCI_RET_SUCCESS;
		return PSCI_RET_NOT_SUPPORTED;
	case PSCI_CPU_SUSPEND:
	case PSCI_SYSTEM_SUSPEND:
		if (atmel_pm_suspend_available())
			return PSCI_RET_SUCCESS;
		return PSCI_RET_NOT_SUPPORTED;
	default:
		return PSCI_RET_NOT_SUPPORTED;
	}
}

uint32_t psci_version(void)
{
	return PSCI_VERSION_1_0;
}
