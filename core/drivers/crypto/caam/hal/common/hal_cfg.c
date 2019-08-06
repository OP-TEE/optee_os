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
#ifdef CFG_CAAM_DT
#include <kernel/dt.h>
#include <kernel/generic_boot.h>
#include <libfdt.h>
#else
#include <caam_hal_ctrl.h>
#include <mm/core_memprot.h>
#include <registers/jr_regs.h>
#endif /* CFG_CAAM_DT */

#ifdef CFG_CAAM_DT
static const char *dt_ctrl_match_table = {
	"fsl,sec-v4.0-ctrl",
};

static const char *dt_jr_match_table = {
	"fsl,sec-v4.0-job-ring",
};

/**
 * Finds the Job Ring reserved for the Secure Mode in the DTB
 *
 * @fdt         Reference to the Device Tree
 * @status      Status mask flag of the node to found
 * @start_node  [in/out] Node offset to start in DTB, current node found
 */
static paddr_t find_jr_index(void *fdt, int status, int *start_node)
{
	paddr_t jr_offset = 0;
	int node;

	node = fdt_node_offset_by_compatible(fdt, *start_node,
					     dt_jr_match_table);

	while (node != -FDT_ERR_NOTFOUND) {
		HAL_TRACE("Found Job Ring node status 0x%x", node);
		if (_fdt_get_status(fdt, node) & status) {
			HAL_TRACE("Found Job Ring node @%d", node);
			jr_offset = _fdt_reg_base_address(fdt, node);
			*start_node = node;
			break;
		}

		node = fdt_node_offset_by_compatible(fdt, node,
						     dt_jr_match_table);
	}

	HAL_TRACE("JR Base address return 0x%" PRIxPTR, jr_offset);
	return jr_offset;
}
#endif /* CFG_CAAM_DT */

/*
 * Returns the Job Ring configuration to be used by the TEE
 *
 * @jrcfg   [out] Job Ring configuration
 */
enum CAAM_Status caam_hal_cfg_get_conf(struct caam_jrcfg *jrcfg)
{
	enum CAAM_Status retstatus = CAAM_FAILURE;
	vaddr_t ctrl_base = 0;

#ifdef CFG_CAAM_DT
	paddr_t jr_offset = 0;
	size_t size = 0;

	void *fdt = NULL;
	int node = 0;

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
	if (dt_enable_secure_status(fdt, node)) {
		EMSG("Not able to set CAAM Control DTB entry secure\n");
		goto exit_get_conf;
	}

	/* Map the device in the system if not already present */
	if (dt_map_dev(fdt, node, &ctrl_base, &size) < 0) {
		HAL_TRACE("CAAM device not defined or not enabled\n");
		goto exit_get_conf;
	}

	jr_offset = find_jr_index(fdt, DT_STATUS_OK_SEC, &node);
	if (jr_offset == 0) {
		EMSG("No Job Ring defined in DTB\n");
		goto exit_get_conf;
	}

	/* We took one job ring, make it unavailable for Normal World */
	if (dt_disable_status(fdt, node)) {
		EMSG("Not able to disable JR DTB entry\n");
		goto exit_get_conf;
	}

	jrcfg->base = ctrl_base;
	jrcfg->offset = jr_offset;
	jrcfg->nb_jobs = NB_JOBS_QUEUE;

	/* Get the job ring interrupt */
	jrcfg->it_num = dt_get_irq(fdt, node);
	if (jrcfg->it_num == DT_INFO_INVALID_INTERRUPT) {
		EMSG("Job Ring interrupt number not defined in DTB\n");
		goto exit_get_conf;
	}
	/* Add index of the first SPI interrupt */
	jrcfg->it_num += 32;
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

	jrcfg->base = ctrl_base;
	jrcfg->offset = (CFG_JR_INDEX + 1) * JRx_BLOCK_SIZE;
	jrcfg->nb_jobs = NB_JOBS_QUEUE;
	/* Add index of the first SPI interrupt */
	jrcfg->it_num = CFG_JR_IRQ;
#endif /* CFG_CAAM_DT */

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

#ifdef CFG_CAAM_DT
	void *fdt = NULL;
	int node = 0;

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
		jr_offset = find_jr_index(fdt, DT_STATUS_OK_SEC, &node);
		if (jr_offset != 0) {
			status = caam_hal_jr_setowner(ctrl_base, jr_offset,
						      JROWN_ARM_NS);
			HAL_TRACE("JR setowner returned %x", status);
			if (status == CAAM_NO_ERROR)
				caam_hal_jr_prepare_backup(ctrl_base,
							   jr_offset);
		}
	} while (jr_offset != 0);

#else
	uint8_t jrnum = 0;

	jrnum = caam_hal_ctrl_jrnum(ctrl_base);

	/* Configure the other Job ring to be Non-Secure */
	do {
#ifdef CFG_CRYPTO_DRIVER
		/*
		 * When the Cryptographic driver is enabled, keep the
		 * Secure Job Ring don't release it.
		 */
		if (jrnum == (CFG_JR_INDEX + 1))
			continue;
#endif
		jr_offset = jrnum * JRx_BLOCK_SIZE;
		status = caam_hal_jr_setowner(ctrl_base, jr_offset,
					      JROWN_ARM_NS);
		if (status == CAAM_NO_ERROR)
			caam_hal_jr_prepare_backup(ctrl_base, jr_offset);
	} while (--jrnum);

#endif /* CFG_CAAM_DT */
}
