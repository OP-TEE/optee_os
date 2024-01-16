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
#include <drivers/imx_snvs.h>
#include <platform_config.h>
#include <registers/ctrl_regs.h>
#include <registers/jr_regs.h>
#include <registers/version_regs.h>
#include <kernel/panic.h>

uint8_t caam_hal_ctrl_era(vaddr_t baseaddr)
{
	/* Read the number of instance */
	uint32_t val = io_caam_read32(baseaddr + CCBVID);

	return GET_CCBVID_CAAM_ERA(val);
}

uint8_t caam_hal_ctrl_jrnum(vaddr_t baseaddr)
{
	uint32_t val = 0;
	uint8_t jrnum = 0;

	if (caam_hal_ctrl_era(baseaddr) < 10) {
		val = io_caam_read32(baseaddr + CHANUM_MS);
		jrnum = GET_CHANUM_MS_JRNUM(val);
	} else {
		val = io_caam_read32(baseaddr + JR_VERSION);
		jrnum = GET_JR_VERSION_JRNUM(val);
	}

	return jrnum;
}

uint8_t caam_hal_ctrl_hash_limit(vaddr_t baseaddr)
{
	uint32_t val = 0;

	if (caam_hal_ctrl_era(baseaddr) < 10) {
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
	} else {
		/* Read the number of instance */
		val = io_caam_read32(baseaddr + MDHA_VERSION);

		if (GET_MDHA_VERSION_MDNUM(val)) {
			/* Hashing is supported */
			val &= BM_MDHA_VERSION_MDVID;
			if (val == MDHA_VERSION_MDVID_LP256)
				return TEE_MAIN_ALGO_SHA256;

			return TEE_MAIN_ALGO_SHA512;
		}
	}

	return UINT8_MAX;
}

bool caam_hal_ctrl_splitkey_support(vaddr_t baseaddr)
{
	uint32_t val = io_caam_read32(baseaddr + CTPR_LS);

	return GET_CTPR_LS_SPLIT_KEY(val);
}

uint8_t caam_hal_ctrl_pknum(vaddr_t baseaddr)
{
	uint32_t val = 0;
	uint8_t pknum = 0;

	if (caam_hal_ctrl_era(baseaddr) < 10) {
		val = io_caam_read32(baseaddr + CHANUM_LS);
		pknum = GET_CHANUM_LS_PKNUM(val);
	} else {
		val = io_caam_read32(baseaddr + PKHA_VERSION);
		pknum = GET_PKHA_VERSION_PKNUM(val);
	}

	return pknum;
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

#ifdef CFG_NXP_CAAM_MP_DRV
uint8_t caam_hal_ctrl_get_mpcurve(vaddr_t ctrl_addr)
{
	uint32_t val_scfgr = 0;

	/*
	 * On i.MX8MQ B0, the MP is not usable, hence
	 * return UINT8_MAX
	 */
	if (soc_is_imx8mq_b0_layer())
		return UINT8_MAX;

	/*
	 * Verify if the device is closed or not
	 * If device is closed, check get the MPCurve
	 */
	if (snvs_is_device_closed()) {
		/* Get the SCFGR content */
		val_scfgr = io_caam_read32(ctrl_addr + SCFGR);

		/* Get the MPCurve field value - 4 bits */
		val_scfgr = (val_scfgr & BM_SCFGR_MPCURVE) >> BS_SCFGR_MPCURVE;

		/*
		 * If the device is closed and the MPCurve field is 0
		 * return UINT8_MAX indicating that there is a problem and the
		 * MP can not be supported.
		 */
		if (!val_scfgr)
			return UINT8_MAX;
	}

	return val_scfgr;
}

TEE_Result caam_hal_ctrl_read_mpmr(vaddr_t ctrl_addr, struct caambuf *mpmr)
{
	unsigned int i = 0;
	uint32_t val = 0;

	if (mpmr->length < MPMR_NB_REG) {
		mpmr->length = MPMR_NB_REG;
		return TEE_ERROR_SHORT_BUFFER;
	}

	/* MPMR endianness is reverted between write and read */
	for (i = 0; i < MPMR_NB_REG; i += 4) {
		val = io_caam_read32(ctrl_addr + MPMR + i);
		mpmr->data[i] = (uint8_t)(val >> 24);
		mpmr->data[i + 1] = (uint8_t)(val >> 16);
		mpmr->data[i + 2] = (uint8_t)(val >> 8);
		mpmr->data[i + 3] = (uint8_t)val;
	}

	mpmr->length = MPMR_NB_REG;
	return TEE_SUCCESS;
}

bool caam_hal_ctrl_is_mp_set(vaddr_t ctrl_addr)
{
	return io_caam_read32(ctrl_addr + SCFGR) & BM_SCFGR_MPMRL;
}

void caam_hal_ctrl_fill_mpmr(vaddr_t ctrl_addr, struct caambuf *msg_mpmr)
{
	size_t i = 0;
	vaddr_t reg = ctrl_addr + MPMR;
	bool is_filled = false;
	uint32_t val = 0;
	size_t min_size = 0;
	size_t remain_size = 0;

	/* check if the MPMR is filled */
	is_filled = caam_hal_ctrl_is_mp_set(ctrl_addr);

	DMSG("is_filled = %s", is_filled ? "true" : "false");

	if (!is_filled) {
		/*
		 * Fill the MPMR with the most significant input value and
		 * complete with 0's if value too short.
		 */
		min_size = MIN(msg_mpmr->length, (size_t)MPMR_NB_REG);
		remain_size = min_size % 4;

		for (i = 0; i < min_size - remain_size; i += 4, reg += 4) {
			val = msg_mpmr->data[i] | msg_mpmr->data[i + 1] << 8 |
			      msg_mpmr->data[i + 2] << 16 |
			      msg_mpmr->data[i + 3] << 24;
			io_caam_write32(reg, val);
		}

		/* Last input bytes value */
		if (remain_size) {
			val = 0;

			/*
			 * Fill the MPMR with the 8 bits values
			 * until the end of the message length
			 */
			for (i = 0; i < remain_size; i++)
				val |= msg_mpmr->data[i] << (i * 8);
			io_caam_write32(reg, val);
			reg += 4;
		}

		/* Complete with 0's */
		remain_size = (MPMR_NB_REG - ROUNDUP(msg_mpmr->length, 4)) / 4;
		for (i = 0; i < remain_size; i++, reg += 4)
			io_caam_write32(reg, 0x0);

		/*
		 * Locks the MPMR for writing and remains locked until
		 * the next power-on session.
		 */
		io_caam_write32(ctrl_addr + SCFGR,
				io_caam_read32(ctrl_addr + SCFGR) |
				BM_SCFGR_MPMRL);

		DMSG("val_scfgr = %#"PRIx32, io_caam_read32(ctrl_addr + SCFGR));
	}
}
#endif /* CFG_NXP_CAAM_MP_DRV */

#ifdef CFG_NXP_CAAM_SM_DRV
vaddr_t caam_hal_ctrl_get_smvaddr(vaddr_t ctrl_addr, paddr_t jr_offset)
{
	/*
	 * The Secure Memory Virtual Base Address contains only the upper
	 * bits of the base address of Secure Memory in this Job Ring's virtual
	 * address space. Since the base address of Secure Memory must be on a
	 * 64 kbyte boundary, the least significant 16 bits are omitted.
	 */
	return io_caam_read32(ctrl_addr + JRX_SMVBAR(JRX_IDX(jr_offset))) << 16;
}
#endif /* CFG_NXP_CAAM_SM_DRV */
