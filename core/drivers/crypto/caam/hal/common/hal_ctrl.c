// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2020 NXP
 *
 * Brief   CAAM Controller Hardware Abstration Layer.
 *         Implementation of primitives to access HW.
 */
#include <caam_hal_ctrl.h>
#include <caam_io.h>
#include <caam_trace.h>
#include <config.h>
#include <registers/ctrl_regs.h>
#include <registers/version_regs.h>
#include <kernel/panic.h>

uint8_t caam_hal_ctrl_jrnum(vaddr_t baseaddr)
{
	uint32_t val = 0;

	val = io_caam_read32(baseaddr + CHANUM_MS);

	return GET_CHANUM_MS_JRNUM(val);
}

uint8_t caam_hal_ctrl_hash_limit(vaddr_t baseaddr)
{
	uint32_t val = 0;

	/* Read the number of instance */
	val = io_caam_read32(baseaddr + CHANUM_LS);

	if (GET_CHANUM_LS_MDNUM(val)) {
		/* Hashing is supported */
		val = io_caam_read32(baseaddr + CHAVID_LS);
		val &= BM_CHAVID_LS_MDVID;
		if (val == CHAVID_LS_MDVID_LP256)
			return TEE_MAIN_ALGO_SHA256;

		return TEE_MAIN_ALGO_SHA512;
	}

	return UINT8_MAX;
}

bool caam_hal_ctrl_splitkey_support(vaddr_t baseaddr)
{
	uint32_t val = io_caam_read32(baseaddr + CAAMVID_MS);

	return GET_CAAMVID_MS_MAJ_REV(val) >= 3;
}

uint8_t caam_hal_ctrl_pknum(vaddr_t baseaddr)
{
	uint32_t val = 0;

	val = io_caam_read32(baseaddr + CHANUM_LS);

	return GET_CHANUM_LS_PKNUM(val);
}

uint8_t caam_hal_ctrl_era(vaddr_t baseaddr)
{
	uint32_t val = 0;

	/* Read the number of instance */
	val = io_caam_read32(baseaddr + CCBVID);

	return GET_CCBVID_CAAM_ERA(val);
}

#define PRIBLOB_MASK	GENMASK_32(1, 0)

void caam_hal_ctrl_inc_priblob(vaddr_t baseaddr)
{
	uint32_t val = 0;
	uint32_t blob = 0;

	if (!IS_ENABLED(CFG_CAAM_INC_PRIBLOB))
		return;

	val = io_caam_read32(baseaddr + SCFGR);
	val &= PRIBLOB_MASK;
	CTRL_TRACE("Reading CAAM PRIBLOB: 0x%"PRIx32, val);

	if (val == 0 || val == 2)
		blob = val + 1;
	else if (val == 1)
		blob = val + 2;
	else
		panic("Error locking PRIBLOB, PRIBLOB =3");

	CTRL_TRACE("New CAAM PRIBLOB value: 0x%"PRIx32, blob);

	val = io_caam_read32(baseaddr + SCFGR);
	val |= blob;
	io_caam_write32(baseaddr + SCFGR, val);

	val = io_caam_read32(baseaddr + SCFGR);
	val &= PRIBLOB_MASK;
	CTRL_TRACE("Checking: CAAM PRIBLOB: 0x%"PRIx32 " want: 0x%"PRIx32, val,
		   blob);
	if (val != blob)
		panic("Written PRIBLOB and read PRIBLOB do not match!");
}
