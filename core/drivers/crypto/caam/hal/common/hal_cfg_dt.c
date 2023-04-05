// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2017-2019, 2021 NXP
 *
 * Brief   CAAM Configuration.
 */
#include <caam_common.h>
#include <caam_hal_cfg.h>
#include <caam_hal_jr.h>
#include <caam_jr.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <kernel/interrupt.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>

static const char *dt_caam_match_table = {
	"fsl,sec-v4.0",
};

static const char *dt_jr_match_table = {
	"fsl,sec-v4.0-job-ring",
};

/*
 * Finds the Job Ring reserved for the Secure Mode in the DTB
 *
 * @fdt         Reference to the Device Tree
 * @status      Status mask flag of the node to found
 * @find_node   [out] Node offset found
 */
static paddr_t find_jr_offset(void *fdt, int status, int *find_node)
{
	paddr_t jr_offset = 0;
	int node = fdt_node_offset_by_compatible(fdt, 0, dt_jr_match_table);

	for (; node != -FDT_ERR_NOTFOUND;
	     node = fdt_node_offset_by_compatible(fdt, node,
						  dt_jr_match_table)) {
		HAL_TRACE("Found Job Ring node status @%" PRId32, node);
		if (fdt_get_status(fdt, node) == status) {
			HAL_TRACE("Found Job Ring node @%" PRId32, node);
			jr_offset = fdt_reg_base_address(fdt, node);
			*find_node = node;
			break;
		}
	}

	HAL_TRACE("JR Offset return 0x%" PRIxPTR, jr_offset);
	return jr_offset;
}

void caam_hal_cfg_get_ctrl_dt(void *fdt, vaddr_t *ctrl_base)
{
	size_t size = 0;
	int node = 0;
	paddr_t pctrl_base = 0;

	*ctrl_base = 0;
	/* Get the CAAM Node to get the controller base address */
	node = fdt_node_offset_by_compatible(fdt, 0, dt_caam_match_table);

	if (node < 0)
		return;

	/*
	 * Map CAAM controller base address as Secure IO if not
	 * already present in the MMU table.
	 * Then get the virtual address of the CAAM controller
	 */
	pctrl_base = fdt_reg_base_address(fdt, node);
	if (pctrl_base == DT_INFO_INVALID_REG) {
		HAL_TRACE("CAAM control base address not defined");
		return;
	}

	size = fdt_reg_size(fdt, node);
	if (size == DT_INFO_INVALID_REG_SIZE) {
		HAL_TRACE("CAAM control base address size not defined");
		return;
	}

	*ctrl_base = (vaddr_t)core_mmu_add_mapping(MEM_AREA_IO_SEC, pctrl_base,
						   size);
	if (!*ctrl_base) {
		EMSG("CAAM control base MMU PA mapping failure");
		return;
	}

	HAL_TRACE("Map Controller 0x%" PRIxVA, *ctrl_base);
}

void caam_hal_cfg_get_jobring_dt(void *fdt, struct caam_jrcfg *jrcfg)
{
	paddr_t jr_offset = 0;
	int jr_it_num = 0;
	int node = 0;

	jr_offset = find_jr_offset(fdt, DT_STATUS_OK_SEC, &node);
	if (jr_offset) {
		if (!is_embedded_dt(fdt)) {
			/* Disable JR for Normal World */
			if (dt_enable_secure_status(fdt, node)) {
				EMSG("Not able to disable JR DTB entry");
				return;
			}
		}

		/* Get the job ring interrupt */
		jr_it_num = dt_get_irq(fdt, node);
		if (jr_it_num == DT_INFO_INVALID_INTERRUPT) {
			EMSG("Job Ring interrupt number not defined in DTB");
			return;
		}

		jrcfg->offset = jr_offset;
		jrcfg->it_num = jr_it_num;
	}
}

void caam_hal_cfg_disable_jobring_dt(void *fdt, struct caam_jrcfg *jrcfg)
{
	int node = fdt_node_offset_by_compatible(fdt, 0, dt_jr_match_table);

	for (; node != -FDT_ERR_NOTFOUND;
	     node = fdt_node_offset_by_compatible(fdt, node,
						  dt_jr_match_table)) {
		HAL_TRACE("Found Job Ring node @%" PRId32, node);
		if (fdt_reg_base_address(fdt, node) == jrcfg->offset) {
			HAL_TRACE("Disable Job Ring node @%" PRId32, node);
			if (dt_enable_secure_status(fdt, node))
				panic();
			break;
		}
	}
}
