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

enum caam_status caam_hal_jr_setowner(vaddr_t ctrl_base, paddr_t jr_offset,
				      enum caam_jr_owner owner)
{
	uint32_t val = 0;
	unsigned int jr_idx = JRX_IDX(jr_offset);

	if (owner == JROWN_ARM_S) {
		/* Read the Job Ring Lock bit */
		val = io_caam_read32(ctrl_base + JRxMIDR_MS(jr_idx));
		HAL_TRACE("JR%" PRIu32 "MIDR_MS value 0x%" PRIx32, jr_idx, val);
		val |= JRxMIDR_MS_TZ;

		io_caam_write32(ctrl_base + JRxMIDR_MS(jr_idx), val);
	}

	return CAAM_NO_ERROR;
}

void caam_hal_jr_prepare_backup(vaddr_t ctrl_base __unused,
				paddr_t jr_offset __unused)
{
}
