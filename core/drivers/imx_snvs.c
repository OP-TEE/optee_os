// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2020 Pengutronix
 * Rouven Czerwinski <entwicklung@pengutronix.de>
 * Copyright 2022 NXP
 */

#include <io.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <stdint.h>
#include <tee/tee_fs.h>
#include <types_ext.h>
#include <trace.h>

#define SNVS_HPSR 0x14

#define HPSR_SSM_ST_MASK  GENMASK_32(11, 8)
#define HPSR_SSM_ST_SHIFT 8

#define SNVS_HPSR_SYS_SECURITY_BAD    BIT(14)
#define SNVS_HPSR_SYS_SECURITY_CLOSED BIT(13)
#define SNVS_HPSR_SYS_SECURITY_OPEN   BIT(12)

enum snvs_ssm_mode {
	SNVS_SSM_MODE_INIT,
	SNVS_SSM_MODE_HARD_FAIL,
	SNVS_SSM_MODE_SOFT_FAIL = 3,
	SNVS_SSM_MODE_INIT_INTERMEDIATE = 8,
	SNVS_SSM_MODE_CHECK,
	SNVS_SSM_MODE_NON_SECURE = 11,
	SNVS_SSM_MODE_TRUSTED = 13,
	SNVS_SSM_MODE_SECURE,
};

enum snvs_security_cfg {
	SNVS_SECURITY_CFG_FAB,
	SNVS_SECURITY_CFG_OPEN,
	SNVS_SECURITY_CFG_CLOSED,
	SNVS_SECURITY_CFG_FIELD_RETURN,
};

#ifdef CFG_RPMB_FS
static enum snvs_security_cfg snvs_get_security_cfg(void)
{
	vaddr_t snvs = core_mmu_get_va(SNVS_BASE, MEM_AREA_IO_SEC,
				       SNVS_HPSR + sizeof(uint32_t));
	uint32_t val = 0;

	val = io_read32(snvs + SNVS_HPSR);
	DMSG("HPSR: 0x%"PRIx32, val);
	if (val & SNVS_HPSR_SYS_SECURITY_BAD)
		return SNVS_SECURITY_CFG_FIELD_RETURN;
	else if (val & SNVS_HPSR_SYS_SECURITY_CLOSED)
		return SNVS_SECURITY_CFG_CLOSED;
	else if (val & SNVS_HPSR_SYS_SECURITY_OPEN)
		return SNVS_SECURITY_CFG_OPEN;
	else if (val > 4 && val < 8)
		return SNVS_SECURITY_CFG_OPEN;

	return SNVS_SECURITY_CFG_FAB;
}

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
	enum snvs_security_cfg security = SNVS_SECURITY_CFG_OPEN;
	bool ssm_secure = false;

	mode = snvs_get_ssm_mode();
	security = snvs_get_security_cfg();
	ssm_secure = (mode == SNVS_SSM_MODE_TRUSTED ||
		      mode == SNVS_SSM_MODE_SECURE);

	/*
	 * On i.MX6SDL and i.MX6DQ, the security cfg always returns
	 * SNVS_SECURITY_CFG_FAB (000), therefore we ignore the security
	 * configuration for this SoC.
	 */
	if (soc_is_imx6sdl() || soc_is_imx6dq())
		return ssm_secure;

	return ssm_secure && (security == SNVS_SECURITY_CFG_CLOSED);
}
#endif /* CFG_RPMB_FS */
