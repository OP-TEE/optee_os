// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2020 Pengutronix
 * Rouven Czerwinski <entwicklung@pengutronix.de>
 */

#include <io.h>
#include <drivers/imx_snvs.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <stdint.h>
#include <types_ext.h>
#include <trace.h>

enum snvs_security_cfg snvs_get_security_cfg(void)
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

enum snvs_ssm_mode snvs_get_ssm_mode(void)
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
