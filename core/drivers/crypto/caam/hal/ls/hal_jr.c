// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2019 NXP
 *
 * Brief   CAAM Job Rings Hardware Abstration Layer.
 *         Implementation of primitives to access HW.
 */
#include <caam_common.h>
#include <caam_hal_jr.h>
#include <caam_io.h>
#include <registers/ctrl_regs.h>
#include <registers/jr_regs.h>

/*
 * Configures the Job Ring Owner and lock it.
 * If the configuration is already locked, checks if the configuration
 * set and returns an error if value is not corresponding to the
 * expected value.
 *
 * @ctrl_base  Base address of the controller
 * @jr_offset  Job Ring offset to configure
 * @owner      Onwer ID to configure
 */
enum CAAM_Status caam_hal_jr_setowner(vaddr_t ctrl_base, paddr_t jr_offset,
				      enum caam_jr_owner owner)
{
	uint32_t val = 0;
	uint8_t jr_idx = JRx_IDX(jr_offset);

	if (owner == JROWN_ARM_S) {
		/* Read the Job Ring Lock bit */
		val = io_caam_read32(ctrl_base + JRxMIDR_MS(jr_idx));
		HAL_TRACE("JR%dMIDR_MS value 0x%x", jr_idx, val);
		val |= JRxMIDR_MS_TZ;

		io_caam_write32(ctrl_base + JRxMIDR_MS(jr_idx), val);
	}

	return CAAM_NO_ERROR;
}

/*
 * Let the JR prepare data that need backup
 *
 * @ctrl_base   CAAM JR Base Address
 * @jr_offset   Job Ring offset to prepare backup for
 */
void caam_hal_jr_prepare_backup(vaddr_t ctrl_base __unused,
				paddr_t jr_offset __unused)
{
}
