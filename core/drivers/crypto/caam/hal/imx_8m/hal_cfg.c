// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2024 NXP
 *
 * Brief   CAAM Configuration.
 */
#include <caam_hal_cfg.h>
#include <caam_hal_jr.h>
#include <kernel/dt.h>
#include <registers/jr_regs.h>

void caam_hal_cfg_hab_jr_mgmt(struct caam_jrcfg *jrcfg)
{
	void *fdt = NULL;
	struct caam_jrcfg tmp_jrcfg = {
		.offset = (CFG_JR_HAB_INDEX + 1) * JRX_BLOCK_SIZE,
	};

	fdt = get_dt();
	if (fdt) {
		/* Ensure Secure Job Ring is secure only into DTB */
		caam_hal_cfg_disable_jobring_dt(fdt, &tmp_jrcfg);
	}

	caam_hal_jr_prepare_backup(jrcfg->base, tmp_jrcfg.offset);
}

bool caam_hal_cfg_is_hab_jr(paddr_t jr_offset)
{
	unsigned int jr_idx = JRX_IDX(jr_offset);

	return jr_idx == CFG_JR_HAB_INDEX;
}
