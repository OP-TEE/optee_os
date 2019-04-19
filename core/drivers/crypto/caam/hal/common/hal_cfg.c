// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2017-2019 NXP
 *
 * @file    hal_cfg.c
 *
 * @brief   CAAM Configuration.
 */

#ifdef CFG_CAAM_DT

/* Global includes */
#include <kernel/dt.h>
#include <kernel/generic_boot.h>
#include <libfdt.h>

#else

/* Global includes */
#include <mm/core_memprot.h>

/* Register includes */
#include "jr_regs.h"

#endif // CFG_CAAM_DT

#ifndef	CFG_LS
/* Platform includes */
#include <imx.h>
#endif

/* Local includes */
#include "caam_common.h"
#include "caam_jr.h"

/* Hal includes */
#include "hal_cfg.h"
#include "hal_jr.h"

#ifndef CFG_CAAM_DT
/* Hal includes */
#include "hal_ctrl.h"
#endif // CFG_CAAM_DT

#ifdef CFG_CAAM_DT
static const char *dt_ctrl_match_table = {
	"fsl,sec-v4.0-ctrl",
};

static const char *dt_jr_match_table = {
	"fsl,sec-v4.0-job-ring",
};

#endif // CFG_CAAM_DT

/**
 * @brief   Returns the Job Ring Configuration to be used by the TEE
 *
 * @param[out] jr_cfg   Job Ring Configuration
 *
 * @retval  CAAM_NO_ERROR   Success
 * @retval  CAAM_FAILURE    An error occurred
 */
enum CAAM_Status hal_cfg_get_conf(struct jr_cfg *jr_cfg)
{
	enum CAAM_Status retstatus = CAAM_FAILURE;

	vaddr_t ctrl_base;

#ifdef CFG_CAAM_DT

	paddr_t jr_offset;
	size_t  size;

	void *fdt;
	int  node;

	fdt = get_dt();
	if (!fdt) {
		EMSG("DTB no present\n");
		goto exit_get_conf;
	}

	node = fdt_node_offset_by_compatible(fdt, 0, dt_ctrl_match_table);

	if (node < 0) {
		EMSG("Caam Node not found err = 0x%X\n", node);
		goto exit_get_conf;
	}

	/* Ensure that CAAM Control is secure-status enabled */
	if (dt_set_secure_status(fdt, node)) {
		EMSG("Not able to set CAAM Control DTB entry secure\n");
		goto exit_get_conf;
	}

	/* Map the device in the system if not already present */
	if (dt_map_dev(fdt, node, &ctrl_base, &size) < 0) {
		HAL_TRACE("CAAM device not defined or not enabled\n");
		goto exit_get_conf;
	}

	jr_offset = dt_node_offset_by_compatible_status(fdt,
			DT_STATUS_OK_SEC, &node, dt_jr_match_table);
	if (jr_offset == 0) {
		EMSG("No Job Ring defined in DTB\n");
		goto exit_get_conf;
	}

	/* We took one job ring, make it unavailable for Normal World */
	if (dt_disable_status(fdt, node)) {
		EMSG("Not able to disable JR DTB entry\n");
		goto exit_get_conf;
	}

	jr_cfg->base    = ctrl_base;
	jr_cfg->offset  = jr_offset;
	jr_cfg->nb_jobs = NB_JOBS_QUEUE;

	// Get the job ring interrupt
	jr_cfg->it_num  = dt_get_irq(fdt, node);
	if (jr_cfg->it_num < 0) {
		EMSG("Job Ring interrupt number not defined in DTB\n");
		goto exit_get_conf;
	}
	// Add index of the first SPI interrupt
	jr_cfg->it_num += 32;
#else

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

	jr_cfg->base    = ctrl_base;
	jr_cfg->offset  = (CFG_JR_INDEX + 1) * JRx_BLOCK_SIZE;
	jr_cfg->nb_jobs = NB_JOBS_QUEUE;
	// Add index of the first SPI interrupt
	jr_cfg->it_num  = CFG_JR_IRQ;
#endif // CFG_CAAM_DT

	retstatus = CAAM_NO_ERROR;

exit_get_conf:
	HAL_TRACE("HAL CFG Get Job Ring returned (0x%x)\n", retstatus);
	return retstatus;
}

/**
 * @brief   Setup the Non-Secure Job Ring
 *
 * @param[in] ctrl_base   Virtual CAAM Controller Base address
 *
 */
void hal_cfg_setup_nsjobring(vaddr_t ctrl_base)
{
	enum CAAM_Status status __maybe_unused;

	paddr_t jr_offset;

#ifdef CFG_CAAM_DT

	void *fdt;
	int  node;

	fdt = get_dt();
	if (!fdt) {
		EMSG("DTB no present\n");
		return;
	}

	node = fdt_node_offset_by_compatible(fdt, 0, dt_ctrl_match_table);

	if (node < 0) {
		EMSG("Caam Node not found err = 0x%X\n", node);
		return;
	}

	/* Configure the other Job ring to be Non-Secure */
	do {
		jr_offset = dt_node_offset_by_compatible_status(fdt,
				DT_STATUS_OK_NSEC, &node, dt_jr_match_table);
		if (jr_offset != 0) {
			status = hal_jr_setowner(ctrl_base, jr_offset,
					JROWN_ARM_NS);
			HAL_TRACE("JR setowner returned %x", status);
			if (status == CAAM_NO_ERROR)
				hal_jr_prepare_backup(ctrl_base, jr_offset);
		}
	} while (jr_offset != 0);

#else

	uint8_t jrnum;

	jrnum = hal_ctrl_jrnum(ctrl_base);

	/* Configure the other Job ring to be Non-Secure */
	do {
#ifdef CFG_CRYPTO_DRIVER
		if (jrnum != (CFG_JR_INDEX + 1)) {
			jr_offset = jrnum * JRx_BLOCK_SIZE;
			status = hal_jr_setowner(ctrl_base, jr_offset,
				JROWN_ARM_NS);
			if (status == CAAM_NO_ERROR)
				hal_jr_prepare_backup(ctrl_base, jr_offset);
		}
#else
		jr_offset = jrnum * JRx_BLOCK_SIZE;
		status = hal_jr_setowner(ctrl_base, jr_offset, JROWN_ARM_NS);
		if (status == CAAM_NO_ERROR)
			hal_jr_prepare_backup(ctrl_base, jr_offset);
#endif
	} while (--jrnum);

#endif // CFG_CAAM_DT
}
