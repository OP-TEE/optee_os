// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2019 NXP
 *
 * @file    hal_jr.c
 *
 * @brief   CAAM Job Rings Hardware Abstration Layer.\n
 *          Implementation of primitives to access HW
 */

/* Local includes */
#include "caam_common.h"
#include "caam_io.h"

/* Hal includes */
#include "hal_jr.h"

/* Registers includes */
#include "ctrl_regs.h"
#include "jr_regs.h"

/**
 * @brief   Configures the Job Ring Owner and lock it.\n
 *          If the configuration is already locked, checks if the configuration
 *          set and returns an error if value is not corresponding to the
 *          expected value.
 *
 * @param[in] ctrl_base  Base address of the controller
 * @param[in] jr_offset  Job Ring offset to configure
 * @param[in] owner      Onwer ID to configure
 *
 * @retval   CAAM_NO_ERROR  Success
 * @retval   CAAM_FAILURE   An error occurred
 *
 */
enum CAAM_Status hal_jr_setowner(vaddr_t ctrl_base, paddr_t jr_offset,
					enum jr_owner owner)
{
	uint32_t val;
	uint8_t jr_idx = JRx_IDX(jr_offset);

	if (owner == JROWN_ARM_S) {
		/* Read the Job Ring Lock bit */
		val = get32(ctrl_base + JRxMIDR_MS(jr_idx));
		HAL_TRACE("JR%dMIDR_MS value 0x%x", jr_idx, val);
		val |= JRxMIDR_MS_TZ;

		put32(ctrl_base + JRxMIDR_MS(jr_idx), val);
	}

	return CAAM_NO_ERROR;
}

/**
 * @brief   Let the JR prepare data that need backup
 *
 * @param[in] ctrl_base   CAAM JR Base Address
 * @param[in] jr_offset   Job Ring offset to prepare backup for
 */
void hal_jr_prepare_backup(__unused vaddr_t ctrl_base,
			__unused paddr_t jr_offset)
{
}

