// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2017-2019 NXP
 *
 * Brief   CAAM Configuration.
 */
#include <caam_common.h>
#include <caam_hal_cfg.h>
#include <caam_hal_jr.h>
#include <caam_jr.h>
#include <caam_hal_ctrl.h>
#include <mm/core_memprot.h>
#include <registers/jr_regs.h>

/*
 * Returns the Job Ring configuration to be used by the TEE
 *
 * @jrcfg   [out] Job Ring configuration
 */
enum CAAM_Status caam_hal_cfg_get_conf(struct caam_jrcfg *jrcfg)
{
	enum CAAM_Status retstatus = CAAM_FAILURE;
	vaddr_t ctrl_base = 0;

	ctrl_base = (vaddr_t)phys_to_virt(CAAM_BASE, MEM_AREA_IO_SEC);
	if (!ctrl_base) {
		if (!core_mmu_add_mapping(MEM_AREA_IO_SEC, CAAM_BASE,
					  CORE_MMU_PGDIR_SIZE)) {
			EMSG("Unable to map CAAM Registers");
			goto exit_get_conf;
		}

		ctrl_base = (vaddr_t)phys_to_virt(CAAM_BASE, MEM_AREA_IO_SEC);
	}

	if (!ctrl_base) {
		EMSG("Unable to get the CAAM Base address");
		goto exit_get_conf;
	}

	jrcfg->base = ctrl_base;
	jrcfg->offset = (CFG_JR_INDEX + 1) * JRX_BLOCK_SIZE;
	jrcfg->nb_jobs = NB_JOBS_QUEUE;
	/* Add index of the first SPI interrupt */
	jrcfg->it_num = CFG_JR_INT;

	retstatus = CAAM_NO_ERROR;

exit_get_conf:
	HAL_TRACE("HAL CFG Get Job Ring returned (0x%x)\n", retstatus);
	return retstatus;
}

/*
 * Setup the Non-Secure Job Ring
 *
 * @ctrl_base   Virtual CAAM Controller Base address
 */
void caam_hal_cfg_setup_nsjobring(vaddr_t ctrl_base)
{
	enum CAAM_Status status = CAAM_FAILURE;
	paddr_t jr_offset = 0;
	uint8_t jrnum = 0;

	for (jrnum = caam_hal_ctrl_jrnum(ctrl_base); jrnum; jrnum--) {
#ifdef CFG_CRYPTO_DRIVER
		/*
		 * When the Cryptographic driver is enabled, keep the
		 * Secure Job Ring don't release it.
		 */
		if (jrnum == (CFG_JR_INDEX + 1))
			continue;
#endif
		jr_offset = jrnum * JRX_BLOCK_SIZE;
		status = caam_hal_jr_setowner(ctrl_base, jr_offset,
					      JROWN_ARM_NS);
		if (status == CAAM_NO_ERROR)
			caam_hal_jr_prepare_backup(ctrl_base, jr_offset);
	}
}
