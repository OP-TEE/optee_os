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
	{ JR0MIDR_LS, 1, 0, 0 },
	{ JR0MIDR_MS, 1, 0, 0 },
};

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
	enum CAAM_Status retstatus = CAAM_FAILURE;
	uint32_t val = 0;
	uint32_t cfg_ms = 0;
	uint32_t cfg_ls = 0;
	unsigned int jr_idx = JRX_IDX(jr_offset);

	/* Read the Job Ring Lock bit */
	val = io_caam_read32(ctrl_base + JRxMIDR_MS(jr_idx));
	HAL_TRACE("JR%dMIDR_MS value 0x%x", jr_idx, val);

	/* Prepare the Job Ring MS/LS registers */
	if (owner & JROWNER_SECURE) {
		/* Configuration only lock for the Secure JR */
		cfg_ms = JRxMIDR_MS_JROWN_MID((owner & ~JROWNER_SECURE));
		cfg_ms |= JRxMIDR_MS_AMTD;
#ifdef CFG_CRYPTO_DRIVER
		cfg_ms |= JRxMIDR_MS_LAMTD;
		cfg_ms |= JRxMIDR_MS_LMID;
#endif
		cfg_ls = JRxMIDR_LS_SEQ_MID((owner & ~JROWNER_SECURE));
		cfg_ls |= JRxMIDR_LS_NONSEQ_MID((owner & ~JROWNER_SECURE));
	} else {
		cfg_ms = JRxMIDR_MS_JROWN_MID(owner) | JRxMIDR_MS_JROWN_NS;
		cfg_ls = JRxMIDR_LS_SEQ_MID(owner) | JRxMIDR_LS_SEQ_NS;
		cfg_ls |= JRxMIDR_LS_NONSEQ_MID(owner) | JRxMIDR_LS_NONSEQ_NS;
	}

	/*
	 * If the configuration already locked, check that is the configuration
	 * that we want. If not return in error.
	 */
	if (val & JRxMIDR_MS_LMID) {
		/* Check if the setup configuration is correct or not */
		HAL_TRACE("JR%dMIDR_MS value 0x%x (0x%x)", jr_idx, val, cfg_ms);
		if ((cfg_ms | JRxMIDR_MS_LMID) == val) {
			/*
			 * Read the LS register and compare with expected
			 * value
			 */
			val = io_caam_read32(ctrl_base + JRxMIDR_LS(jr_idx));
			HAL_TRACE("JR%dMIDR_LS value 0x%x (0x%x)", jr_idx, val,
				  cfg_ls);
			if (val == cfg_ls)
				retstatus = CAAM_NO_ERROR;
		}
	} else {
		HAL_TRACE("JR%dMIDR_LS set value 0x%x", jr_idx, cfg_ls);
		HAL_TRACE("JR%dMIDR_MS set value 0x%x", jr_idx, cfg_ms);
		/* Set the configuration */
		io_caam_write32(ctrl_base + JRxMIDR_LS(jr_idx), cfg_ls);
		io_caam_write32(ctrl_base + JRxMIDR_MS(jr_idx), cfg_ms);
		retstatus = CAAM_NO_ERROR;
	}

	return retstatus;
}

/*
 * Let the JR prepare data that need backup
 *
 * @ctrl_base   CAAM JR Base Address
 * @jr_offset   Job Ring offset to prepare backup for
 */
void caam_hal_jr_prepare_backup(vaddr_t ctrl_base, paddr_t jr_offset)
{
	unsigned int jr_idx = JRX_IDX(jr_offset);

	caam_pwr_add_backup(ctrl_base + (jr_idx * JRxMIDR_SIZE), jrcfg_backup,
			    ARRAY_SIZE(jrcfg_backup));
}
