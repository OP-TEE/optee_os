// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018 NXP
 *
 * @file    utils_delay.c
 *
 * @brief   Delay management utilities.\n
 *          Primitive to delay a delay.
 */

/* Global includes */
#include <types_ext.h>
#include <arm.h>

/* Utils includes */
#include "utils_delay.h"

/**
 * @brief   Wait given microsecond
 *
 * @param[in] time  Time in microsecond
 *
 */
void caam_udelay(uint32_t time)
{
	uint32_t counter = time * 500;

	/* Implementation of a Software loop assuming CPU clock of 500MHz */
	while (counter--) {
		isb();
		dsb();
	};
}

