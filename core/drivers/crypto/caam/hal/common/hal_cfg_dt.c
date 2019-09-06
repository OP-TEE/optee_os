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
#include <kernel/dt.h>
#include <libfdt.h>

static const char *dt_ctrl_match_table = {
	"fsl,sec-v4.0-ctrl",
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
	int node = -FDT_ERR_NOTFOUND;

	node = fdt_node_offset_by_compatible(fdt, 0, dt_jr_match_table);

	while (node != -FDT_ERR_NOTFOUND) {
		HAL_TRACE("Found Job Ring node status @%d", node);
		if (_fdt_get_status(fdt, node) == status) {
			HAL_TRACE("Found Job Ring node @%d", node);
			jr_offset = _fdt_reg_base_address(fdt, node);
			*find_node = node;
			break;
		}

		node = fdt_node_offset_by_compatible(fdt, node,
						     dt_jr_match_table);
	}

	HAL_TRACE("JR Offset return 0x%" PRIxPTR, jr_offset);
	return jr_offset;
}

/*
 * Finds the CAAM Controller definition in the DTB.
 * If found, ensures it reserved for the Secure OS and disabled for the RichOS.
 *
 * @fdt         Reference to the Device Tree
 */
static int find_ctrl(void *fdt)
{
	int node = 0;

	/*
	 * Node is defined, check if the CAAM Controller is defined. If not
	 * use HW hard coded value
	 */
	node = fdt_node_offset_by_compatible(fdt, 0, dt_ctrl_match_table);
	if (node < 0) {
		HAL_TRACE("Caam Controller not found err = 0x%X\n", node);
		return -1;
	}

	/* Ensure that CAAM Control is secure-status enabled */
	if (dt_enable_secure_status(fdt, node)) {
		EMSG("Not able to set CAAM Control DTB entry secure\n");
		return -1;
	}

	return node;
}

/*
 * Returns the Job Ring configuration to be used by the TEE
 *
 * @fdt         Device Tree handle
 * @ctrl_base   [out] CAAM Controller base address
 */
void caam_hal_cfg_get_ctrl_dt(void *fdt, vaddr_t *ctrl_base)
{
	size_t size = 0;
	int node = 0;

	/*
	 * Check if the CAAM Controller is defined. If not
	 * use HW hard coded value.
	 */
	node = find_ctrl(fdt);
	if (node > 0) {
		/* Map the device in the system if not already present */
		if (dt_map_dev(fdt, node, ctrl_base, &size) < 0) {
			HAL_TRACE("CAAM device not defined or not enabled\n");
			*ctrl_base = 0;
		}
	}
}

/*
 * Returns the Job Ring configuration to be used by the TEE
 *
 * @fdt     Device Tree handle
 * @jrcfg   [out] Job Ring configuration
 */
void caam_hal_cfg_get_jobring_dt(void *fdt, struct caam_jrcfg *jrcfg)
{
	paddr_t jr_offset = 0;
	int jr_it_num = 0;
	int node = 0;

	jr_offset = find_jr_offset(fdt, DT_STATUS_OK_SEC, &node);
	if (jr_offset) {
		/* We took one job ring, make it unavailable for Normal World */
		if (dt_disable_status(fdt, node)) {
			EMSG("Not able to disable JR DTB entry\n");
			return;
		}

		/* Get the job ring interrupt */
		jr_it_num = dt_get_irq(fdt, node);
		if (jr_it_num == DT_INFO_INVALID_INTERRUPT) {
			EMSG("Job Ring interrupt number not defined in DTB\n");
			return;
		}

		jrcfg->offset = jr_offset;
		/* Add index of the first SPI interrupt */
		jrcfg->it_num = jr_it_num + 32;
	}
}

/*
 * Disable the Job Ring used for the Secure environment into the DTB
 *
 * @fdt     Device Tree handle
 * @jrcfg   Job Ring configuration
 */
void caam_hal_cfg_disable_jobring_dt(void *fdt, struct caam_jrcfg *jrcfg)
{
	int node = 0;

	node = fdt_node_offset_by_compatible(fdt, 0, dt_jr_match_table);

	while (node != -FDT_ERR_NOTFOUND) {
		HAL_TRACE("Found Job Ring node @%d", node);
		if (_fdt_reg_base_address(fdt, node) == jrcfg->offset) {
			HAL_TRACE("Disable Job Ring node @%d", node);
			dt_disable_status(fdt, node);
			break;

		}

		node = fdt_node_offset_by_compatible(fdt, node,
						     dt_jr_match_table);
	}
}

