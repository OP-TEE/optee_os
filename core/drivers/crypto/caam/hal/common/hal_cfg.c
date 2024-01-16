// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2017-2019, 2021 NXP
 *
 * Brief   CAAM Configuration.
 */
#include <caam_common.h>
#include <caam_hal_cfg.h>
#include <caam_hal_ctrl.h>
#include <caam_hal_jr.h>
#include <caam_jr.h>
#include <config.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <mm/core_memprot.h>
#include <registers/jr_regs.h>

enum caam_status caam_hal_cfg_get_conf(struct caam_jrcfg *jrcfg)
{
	enum caam_status retstatus = CAAM_FAILURE;
	vaddr_t ctrl_base = 0;
	void *fdt = NULL;

	fdt = get_dt();

	/*
	 * First get the CAAM Controller base address from the DTB,
	 * if DTB present and if the CAAM Controller defined in it.
	 */
	if (fdt)
		caam_hal_cfg_get_ctrl_dt(fdt, &ctrl_base);

	if (!ctrl_base) {
		ctrl_base = (vaddr_t)core_mmu_add_mapping(MEM_AREA_IO_SEC,
							  CAAM_BASE, CAAM_SIZE);
		if (!ctrl_base) {
			EMSG("Unable to map CAAM Registers");
			goto exit_get_conf;
		}
	}

	jrcfg->base = ctrl_base;

	/*
	 * Next get the Job Ring reserved for the Secure environment
	 * into the DTB. If nothing reserved use the default hard coded
	 * value.
	 */
	if (fdt)
		caam_hal_cfg_get_jobring_dt(fdt, jrcfg);

	if (!jrcfg->offset) {
		jrcfg->offset = (CFG_JR_INDEX + 1) * JRX_BLOCK_SIZE;
		jrcfg->it_num = CFG_JR_INT;

		if (IS_ENABLED(CFG_NXP_CAAM_RUNTIME_JR) &&
		    !is_embedded_dt(fdt)) {
			if (fdt) {
				/* Ensure Secure Job Ring is secure in DTB */
				caam_hal_cfg_disable_jobring_dt(fdt, jrcfg);
			}
		}
	}

	jrcfg->nb_jobs = NB_JOBS_QUEUE;

	retstatus = CAAM_NO_ERROR;

exit_get_conf:
	HAL_TRACE("HAL CFG Get CAAM config ret (0x%x)\n", retstatus);
	return retstatus;
}

void __weak caam_hal_cfg_setup_nsjobring(struct caam_jrcfg *jrcfg)
{
	enum caam_status status = CAAM_FAILURE;
	paddr_t jr_offset = 0;
	uint8_t jrnum = 0;

	for (jrnum = caam_hal_ctrl_jrnum(jrcfg->base); jrnum; jrnum--) {
		jr_offset = jrnum * JRX_BLOCK_SIZE;

#ifdef CFG_NXP_CAAM_RUNTIME_JR
		/*
		 * When the Cryptographic driver is enabled, keep the
		 * Secure Job Ring don't release it.
		 * But save the configuration to restore it when
		 * device reset after suspend.
		 */
		if (jr_offset == jrcfg->offset) {
			caam_hal_jr_prepare_backup(jrcfg->base, jr_offset);
			continue;
		}
#endif
		status = caam_hal_jr_setowner(jrcfg->base, jr_offset,
					      JROWN_ARM_NS);
		if (status == CAAM_NO_ERROR)
			caam_hal_jr_prepare_backup(jrcfg->base, jr_offset);
	}
}
