// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021 Western Digital Corporation or its affiliates.
 * Copyright (c) 2022 Ventana Micro Systems Inc.
 * Copyright (c) 2025 Beijing Institute of Open Source Chip (BOSC)
 *
 * Authors:
 *   Anup Patel <anup.patel@wdc.com>
 *   Huang Borong <huangborong@bosc.ac.cn>
 */

#include <drivers/aplic_priv.h>
#include <drivers/imsic.h>
#include <dt-bindings/interrupt-controller/irq.h>
#include <encoding.h>
#include <io.h>
#include <kernel/dt.h>
#include <kernel/dt_driver.h>
#include <libfdt.h>
#include <tee_api_types.h>
#include <trace.h>

static TEE_Result aplic_parse_fdt_node(const void *fdt, int nodeoff,
				       struct aplic_data *aplic)
{
	const fdt32_t *val = NULL;
	struct imsic_data imsic = { };
	int i = 0;
	int len = 0;
	int noff = -1;
	int rc = -1;
	paddr_t reg_addr = 0;
	size_t reg_size = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (nodeoff < 0 || !aplic || !fdt)
		return TEE_ERROR_BAD_PARAMETERS;

	rc = fdt_reg_info(fdt, nodeoff, &reg_addr, &reg_size);
	if (rc < 0 || !reg_addr || !reg_size)
		return TEE_ERROR_ITEM_NOT_FOUND;
	aplic->aplic_base = core_mmu_get_va(reg_addr, MEM_AREA_IO_SEC,
					    reg_size);
	if (!aplic->aplic_base)
		return TEE_ERROR_GENERIC;
	aplic->size = reg_size;

	val = fdt_getprop(fdt, nodeoff, "riscv,num-sources", &len);
	if (len > 0)
		aplic->num_source = fdt32_to_cpu(*val);

	val = fdt_getprop(fdt, nodeoff, "interrupts-extended", &len);
	if (val && (size_t)len >= (2 * sizeof(fdt32_t))) {
		len = len / sizeof(fdt32_t);
		for (i = 0; i < len; i += 2) {
			if (fdt32_to_cpu(val[i + 1]) == IRQ_M_EXT) {
				aplic->targets_mmode = true;
				break;
			}
		}
		aplic->num_idc = len / 2;

		return TEE_SUCCESS;
	} else if (!val) {
		val = fdt_getprop(fdt, nodeoff, "msi-parent", &len);
		if (val && (size_t)len >= sizeof(fdt32_t)) {
			noff = fdt_node_offset_by_phandle(fdt,
							  fdt32_to_cpu(*val));
			if (noff < 0)
				return TEE_ERROR_ITEM_NOT_FOUND;

			res = imisc_parse_fdt_node(fdt, noff, &imsic);
			if (res)
				return res;

			aplic->targets_mmode = imsic.targets_mmode;

			return TEE_SUCCESS;
		}
	}
	return TEE_ERROR_ITEM_NOT_FOUND;
}

TEE_Result aplic_init_from_device_tree(struct aplic_data *aplic)
{
	void *fdt = NULL;
	int node = FDT_ERR_NOTFOUND;
	TEE_Result res = TEE_ERROR_GENERIC;

	fdt = get_dt();
	if (!fdt) {
		EMSG("Unable to get DTB, APLIC init failed");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	/*
	 * Currently, only the S-level interrupt domain is considered.
	 * If the interrupt domain is M-level, continue traversing.
	 * If it is S-level, return directly.
	 */
	node = fdt_node_offset_by_compatible(fdt, -1, APLIC_COMPATIBLE);
	while (node != -FDT_ERR_NOTFOUND) {
		res = aplic_parse_fdt_node(fdt, node, aplic);
		if (res) {
			EMSG("Parse APLIC node failed");
			return res;
		}

		if (!aplic->targets_mmode)
			return TEE_SUCCESS;

		node = fdt_node_offset_by_compatible(fdt, node,
						     APLIC_COMPATIBLE);
	}

	return TEE_ERROR_ITEM_NOT_FOUND;
}

TEE_Result aplic_set_source_mode(struct aplic_data *aplic, uint32_t source,
				 uint32_t type)
{
	vaddr_t sourcecfg = 0;
	uint32_t sm = APLIC_SOURCECFG_SM_INACTIVE;

	switch (type) {
	case IRQ_TYPE_NONE:
		sm = APLIC_SOURCECFG_SM_INACTIVE;
		break;
	case IRQ_TYPE_EDGE_RISING:
		sm = APLIC_SOURCECFG_SM_EDGE_RISE;
		break;
	case IRQ_TYPE_EDGE_FALLING:
		sm = APLIC_SOURCECFG_SM_EDGE_FALL;
		break;
	case IRQ_TYPE_LEVEL_HIGH:
		sm = APLIC_SOURCECFG_SM_LEVEL_HIGH;
		break;
	case IRQ_TYPE_LEVEL_LOW:
		sm = APLIC_SOURCECFG_SM_LEVEL_LOW;
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	sourcecfg = aplic->aplic_base + APLIC_SOURCECFG_BASE +
				(source - 1) * sizeof(uint32_t);
	io_write32(sourcecfg, sm);

	return TEE_SUCCESS;
}
