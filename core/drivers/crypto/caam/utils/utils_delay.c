// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018 NXP
 *
 * Brief   Delay management utilities.
 *         Primitive to delay a delay.
 */
#include <arm.h>
#include <caam_utils_delay.h>

void caam_udelay(uint32_t time)
{
	uint32_t counter = time * 500;

	/* Implementation of a Software loop assuming CPU clock of 500MHz */
	while (counter--) {
		isb();
		dsb();
	};
}
