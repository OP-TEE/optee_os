// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018-2019 NXP
 *
 * @file    hal_jr.c
 *
 * @brief   CAAM Job Rings Hardware Abstration Layer.\n
 *          Implementation of primitives to access HW
 */

/* Local includes */
#include "caam_common.h"
#include "caam_io.h"
#include "caam_pwr.h"

/* Hal includes */
#include "hal_jr.h"

/* Registers includes */
#include "ctrl_regs.h"
#include "jr_regs.h"

/*
 * List of JR configuration registers to save/restore
 */
const struct reglist jrcfg_backup[] = {
	{JR0MIDR_LS, 1, 0, 0},
	{JR0MIDR_MS, 1, 0, 0},
};

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
	enum CAAM_Status retstatus = CAAM_FAILURE;

	uint32_t val;
	uint32_t cfg_ms;
	uint32_t cfg_ls;
	uint8_t  jr_idx = JRx_IDX(jr_offset);

	/* Read the Job Ring Lock bit */
	val = io_caam_read32(ctrl_base + JRxMIDR_MS(jr_idx));
	HAL_TRACE("JR%dMIDR_MS value 0x%x", jr_idx, val);

	/* Prepare the Job Ring MS/LS registers */
	if (owner & JROWNER_SECURE) {
		/* Configuration only lock for the Secure JR */
		cfg_ms  = JRxMIDR_MS_JROWN_MID((owner & ~JROWNER_SECURE));
		cfg_ms |= JRxMIDR_MS_AMTD;
#ifdef CFG_CRYPTO_DRIVER
		cfg_ms |= JRxMIDR_MS_LAMTD;
		cfg_ms |= JRxMIDR_MS_LMID;
#endif
		cfg_ls  = JRxMIDR_LS_SEQ_MID((owner & ~JROWNER_SECURE));
		cfg_ls |= JRxMIDR_LS_NONSEQ_MID((owner & ~JROWNER_SECURE));
	} else {
		cfg_ms  = JRxMIDR_MS_JROWN_MID(owner) | JRxMIDR_MS_JROWN_NS;
		cfg_ls  = JRxMIDR_LS_SEQ_MID(owner) | JRxMIDR_LS_SEQ_NS;
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
			/* Read the LS register and compare with expected
			 * value
			 */
			val = io_caam_read32(ctrl_base + JRxMIDR_LS(jr_idx));
			HAL_TRACE("JR%dMIDR_LS value 0x%x (0x%x)",
					jr_idx, val, cfg_ls);
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

/**
 * @brief   Let the JR prepare data that need backup
 *
 * @param[in] ctrl_base   CAAM JR Base Address
 * @param[in] jr_offset   Job Ring offset to prepare backup for
 *
 * @retval index of the next entry in the queue
 */
void hal_jr_prepare_backup(vaddr_t ctrl_base, paddr_t jr_offset)
{
	uint8_t jr_idx = JRx_IDX(jr_offset);

	caam_pwr_add_backup(ctrl_base + (jr_idx * JRxMIDR_SIZE),
			jrcfg_backup, ARRAY_SIZE(jrcfg_backup));
}
