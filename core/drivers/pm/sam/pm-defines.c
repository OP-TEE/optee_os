// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, Microchip
 */

#include "at91_pm.h"
#include <drivers/sam/at91_ddr.h>
#include <gen-asm-defines.h>
#include <types_ext.h>

DEFINES
{
	DEFINE(PM_DATA_PMC,		offsetof(struct at91_pm_data, pmc));
	DEFINE(PM_DATA_RAMC0,		offsetof(struct at91_pm_data, ramc));
	DEFINE(PM_DATA_MODE,		offsetof(struct at91_pm_data, mode));
	DEFINE(PM_DATA_SHDWC,		offsetof(struct at91_pm_data, shdwc));
	DEFINE(PM_DATA_SFRBU,		offsetof(struct at91_pm_data, sfrbu));
}
