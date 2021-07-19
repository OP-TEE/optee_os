// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, Microchip
 */

#include <drivers/atmel_rstc.h>
#include <drivers/atmel_shdwc.h>
#include <kernel/panic.h>
#include <sm/psci.h>
#include <sm/std_smc.h>
#include <stdint.h>
#include <trace.h>

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
	default:
		return PSCI_RET_NOT_SUPPORTED;
	}
}

uint32_t psci_version(void)
{
	return PSCI_VERSION_1_0;
}
