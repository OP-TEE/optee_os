// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2020 Pengutronix
 * Rouven Czerwinski <entwicklung@pengutronix.de>
 * Copyright 2022 NXP
 */

#include <drivers/imx_snvs.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <stdint.h>
#include <tee/tee_fs.h>
#include <types_ext.h>
#include <trace.h>

#define SNVS_HPLR   0x00
#define SNVS_HPCOMR 0x04
#define SNVS_HPSR   0x14
#define SNVS_LPLR   0x34
#define SNVS_LPMKCR 0x3C

#define HPSR_SSM_ST_MASK  GENMASK_32(11, 8)
#define HPSR_SSM_ST_SHIFT 8

#define SNVS_HPSR_SYS_SECURITY_CFG_OFFSET 12
#define SNVS_HPSR_SYS_SECURITY_CFG	  GENMASK_32(14, 12)

#define SNVS_HPSR_OTPMK_SYND	      GENMASK_32(24, 16)
#define SNVS_HPSR_OTPMK_ZERO	      BIT(27)

#define SNVS_HPLR_MKS_SL BIT32(9)

#define SNVS_LPLR_MKS_HL BIT32(9)

#define SNVS_HPCOMR_MKS_EN   BIT32(13)
#define SNVS_HPCOMR_NPSWA_EN BIT32(31)

#define SNVS_LPMKCR_MKCR_MKS_SEL GENMASK_32(1, 0)

enum snvs_ssm_mode {
	SNVS_SSM_MODE_INIT,
	SNVS_SSM_MODE_HARD_FAIL,
	SNVS_SSM_MODE_SOFT_FAIL = 3,
	SNVS_SSM_MODE_INIT_INTERMEDIATE = 8,
	SNVS_SSM_MODE_CHECK,
	SNVS_SSM_MODE_NON_SECURE = 11,
	SNVS_SSM_MODE_TRUSTED = 13,
	SNVS_SSM_MODE_SECURE = 15,
};

enum snvs_security_cfg {
	SNVS_SECURITY_CFG_FAB,
	SNVS_SECURITY_CFG_OPEN,
	SNVS_SECURITY_CFG_CLOSED,
	SNVS_SECURITY_CFG_FIELD_RETURN,
};

/*
 * Return true if the master key is OTPMK, false otherwise.
 */
static bool is_otpmk_selected(void)
{
	uint32_t hp_mks = 0;
	vaddr_t base = core_mmu_get_va(SNVS_BASE, MEM_AREA_IO_SEC, SNVS_SIZE);

	hp_mks = io_read32(base + SNVS_HPCOMR);

	/*
	 * The master key selection might be done by the MASTER_KEY_SEL field
	 * of LPMKCR instead.
	 */
	if (hp_mks & SNVS_HPCOMR_MKS_EN) {
		uint32_t lp_mks = io_read32(base + SNVS_LPMKCR);

		if (lp_mks & SNVS_LPMKCR_MKCR_MKS_SEL)
			return false;
	}

	return true;
}

/*
 * Return true if the master key selection is locked, false otherwise.
 */
static bool is_mks_locked(void)
{
	vaddr_t base = core_mmu_get_va(SNVS_BASE, MEM_AREA_IO_SEC, SNVS_SIZE);

	return io_read32(base + SNVS_HPLR) & SNVS_HPLR_MKS_SL ||
	       io_read32(base + SNVS_LPLR) & SNVS_LPLR_MKS_HL;
}

/* Set the Master key to use OTPMK and lock it. */
static void set_mks_otpmk(void)
{
	vaddr_t base = core_mmu_get_va(SNVS_BASE, MEM_AREA_IO_SEC, SNVS_SIZE);

	io_setbits32(base + SNVS_HPCOMR, SNVS_HPCOMR_MKS_EN);
	io_clrbits32(base + SNVS_LPMKCR, SNVS_LPMKCR_MKCR_MKS_SEL);
	io_clrbits32(base + SNVS_HPLR, SNVS_HPLR_MKS_SL);
	io_setbits32(base + SNVS_LPLR, SNVS_LPLR_MKS_HL);
}

/*
 * Return true if OTPMK is valid, false otherwise.
 */
static bool is_otpmk_valid(void)
{
	vaddr_t base = core_mmu_get_va(SNVS_BASE, MEM_AREA_IO_SEC, SNVS_SIZE);
	uint32_t status = io_read32(base + SNVS_HPSR);

	return !(status & (SNVS_HPSR_OTPMK_ZERO | SNVS_HPSR_OTPMK_SYND));
}

static enum snvs_security_cfg snvs_get_security_cfg(void)
{
	uint32_t val = 0;
	vaddr_t base = core_mmu_get_va(SNVS_BASE, MEM_AREA_IO_SEC,
				       SNVS_SIZE);

	val = (io_read32(base + SNVS_HPSR) & SNVS_HPSR_SYS_SECURITY_CFG) >>
	      SNVS_HPSR_SYS_SECURITY_CFG_OFFSET;

	switch (val) {
	case 0b000:
		return SNVS_SECURITY_CFG_FAB;
	case 0b001:
		return SNVS_SECURITY_CFG_OPEN;
	case 0b011:
		return SNVS_SECURITY_CFG_CLOSED;
	default:
		return SNVS_SECURITY_CFG_FIELD_RETURN;
	}
}

bool snvs_is_device_closed(void)
{
	return (snvs_get_security_cfg() == SNVS_SECURITY_CFG_CLOSED);
}

#ifdef CFG_RPMB_FS
static enum snvs_ssm_mode snvs_get_ssm_mode(void)
{
	vaddr_t snvs = core_mmu_get_va(SNVS_BASE, MEM_AREA_IO_SEC,
				       SNVS_HPSR + sizeof(uint32_t));
	uint32_t val = 0;

	val = io_read32(snvs + SNVS_HPSR);
	val &= HPSR_SSM_ST_MASK;
	val = val >> HPSR_SSM_ST_SHIFT;
	DMSG("HPSR: SSM ST Mode: 0x%01"PRIx32, val);
	return val;
}

bool plat_rpmb_key_is_ready(void)
{
	enum snvs_ssm_mode mode = SNVS_SSM_MODE_INIT;
	bool ssm_secure = false;

	mode = snvs_get_ssm_mode();
	ssm_secure = (mode == SNVS_SSM_MODE_TRUSTED ||
		      mode == SNVS_SSM_MODE_SECURE);

	/*
	 * On i.MX6SDL and i.MX6DQ, the security cfg always returns
	 * SNVS_SECURITY_CFG_FAB (000), therefore we ignore the security
	 * configuration for this SoC.
	 */
	if (soc_is_imx6sdl() || soc_is_imx6dq())
		return ssm_secure;

	return ssm_secure && snvs_is_device_closed();
}
#endif /* CFG_RPMB_FS */

TEE_Result imx_snvs_set_master_otpmk(void)
{
	if (!is_otpmk_valid())
		return TEE_ERROR_BAD_STATE;

	if (is_mks_locked()) {
		if (is_otpmk_selected())
			return TEE_SUCCESS;

		return TEE_ERROR_BAD_STATE;
	}

	set_mks_otpmk();

	return TEE_SUCCESS;
}
