// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2019 NXP
 *
 * Brief   CAAM Job Rings Hardware Abstration Layer.
 *         Implementation of primitives to access HW.
 */
#include <caam_common.h>
#include <caam_hal_jr.h>
#include <caam_io.h>
#include <caam_pwr.h>
#include <registers/ctrl_regs.h>
#include <registers/jr_regs.h>

/*
 * List of JR configuration registers to save/restore
 */
static const struct reglist jrcfg_backup[] = {
	BACKUP_REG(JR0MIDR_LS, 1, 0, 0),
	BACKUP_REG(JR0MIDR_MS, 1, 0, 0),
};

enum caam_status caam_hal_jr_setowner(vaddr_t ctrl_base, paddr_t jr_offset,
				      enum caam_jr_owner owner)
{
	enum caam_status retstatus = CAAM_FAILURE;
	uint32_t val = 0;
	uint32_t cfg_ms = 0;
	uint32_t cfg_ls = 0;
	unsigned int jr_idx = JRX_IDX(jr_offset);

	/* Read the Job Ring Lock bit */
	val = io_caam_read32(ctrl_base + JRxMIDR_MS(jr_idx));
	HAL_TRACE("JR%" PRIu32 "MIDR_MS value 0x%" PRIx32, jr_idx, val);

	/* Prepare the Job Ring MS/LS registers */
	if (owner & JROWNER_SECURE) {
		/* Configuration only lock for the Secure JR */
		cfg_ms = JRxMIDR_MS_JROWN_MID(owner & ~JROWNER_SECURE);
		cfg_ms |= JRxMIDR_MS_AMTD;
#ifdef CFG_NXP_CAAM_RUNTIME_JR
		cfg_ms |= JRxMIDR_MS_LAMTD;
		cfg_ms |= JRxMIDR_MS_LMID;
#endif
		cfg_ls = JRxMIDR_LS_SEQ_MID(owner & ~JROWNER_SECURE);
		cfg_ls |= JRxMIDR_LS_NONSEQ_MID(owner & ~JROWNER_SECURE);
	} else {
		cfg_ms = JRxMIDR_MS_JROWN_MID(owner) | JRxMIDR_MS_JROWN_NS;
		cfg_ls = JRxMIDR_LS_SEQ_MID(owner) | JRxMIDR_LS_SEQ_NS;
		cfg_ls |= JRxMIDR_LS_NONSEQ_MID(owner) | JRxMIDR_LS_NONSEQ_NS;
	}

	if (val & JRxMIDR_MS_LMID) {
		/*
		 * Configuration already locked, check it is the
		 * expected configuration.
		 */
		HAL_TRACE("JR%" PRIu32 "MIDR_MS value 0x%" PRIx32 " (0x%" PRIx32
			  ")",
			  jr_idx, val, cfg_ms);
		if ((cfg_ms | JRxMIDR_MS_LMID) == val) {
			/*
			 * Read the LS register and compare with expected
			 * value
			 */
			val = io_caam_read32(ctrl_base + JRxMIDR_LS(jr_idx));
			HAL_TRACE("JR%" PRIu32 "MIDR_LS value 0x%" PRIx32
				  " (0x%" PRIX32 ")",
				  jr_idx, val, cfg_ls);
			if (val == cfg_ls)
				retstatus = CAAM_NO_ERROR;
		}
	} else {
		HAL_TRACE("JR%" PRIu32 "MIDR_LS set value 0x%" PRIx32, jr_idx,
			  cfg_ls);
		HAL_TRACE("JR%" PRIu32 "MIDR_MS set value 0x%" PRIx32, jr_idx,
			  cfg_ms);
		/* Set the configuration */
		io_caam_write32(ctrl_base + JRxMIDR_LS(jr_idx), cfg_ls);
		io_caam_write32(ctrl_base + JRxMIDR_MS(jr_idx), cfg_ms);
		retstatus = CAAM_NO_ERROR;
	}

	return retstatus;
}

void caam_hal_jr_prepare_backup(vaddr_t ctrl_base, paddr_t jr_offset)
{
	unsigned int jr_idx = JRX_IDX(jr_offset);

	caam_pwr_add_backup(ctrl_base + (jr_idx * JRxMIDR_SIZE), jrcfg_backup,
			    ARRAY_SIZE(jrcfg_backup));
}
