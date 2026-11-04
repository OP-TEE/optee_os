// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/qcom/xpuv4.h>
#include <kernel/dt.h>
#include <libfdt.h>
#include <qcom_common.h>
#include <trace.h>
#include <util.h>

/* The most DRAM windows that the embedded DT can describe */
#define DDR_GUARDS_MAX		4

static struct xpu4_guard ddr_guards[DDR_GUARDS_MAX];

static TEE_Result add_node_guards(const void *fdt, int node, size_t *count)
{
	size_t tuple_len = 0;
	int addr_cells = 0;
	int size_cells = 0;
	int parent = 0;
	int len = 0;
	size_t i = 0;

	if (!fdt_getprop(fdt, node, "reg", &len))
		return TEE_ERROR_BAD_STATE;

	parent = fdt_parent_offset(fdt, node);
	if (parent < 0)
		return TEE_ERROR_BAD_STATE;

	addr_cells = fdt_address_cells(fdt, parent);
	size_cells = fdt_size_cells(fdt, parent);
	if (addr_cells <= 0 || size_cells <= 0)
		return TEE_ERROR_BAD_STATE;

	/* Only a whole number of windows is a reg that can be trusted */
	tuple_len = (addr_cells + size_cells) * sizeof(fdt32_t);
	if (!len || (size_t)len % tuple_len)
		return TEE_ERROR_BAD_STATE;

	for (i = 0; i < (size_t)len / tuple_len; i++) {
		paddr_t base = 0;
		size_t size = 0;

		if (fdt_get_reg_props_by_index(fdt, node, i, &base, &size))
			return TEE_ERROR_BAD_STATE;

		if (*count == ARRAY_SIZE(ddr_guards)) {
			EMSG("XPU: no room to guard DRAM %#" PRIxPA "+%#zx",
			     base, size);
			return TEE_ERROR_OUT_OF_MEMORY;
		}

		ddr_guards[*count].start = base;
		ddr_guards[*count].size = size;
		(*count)++;
	}

	return TEE_SUCCESS;
}

/*
 * The DRAM is what the enabled memory nodes of the embedded DT describe. What
 * cannot be read or does not fit is reported and left unguarded, so a region
 * in it is refused.
 */
TEE_Result qcom_xpu_get_ddr_guards(const struct xpu4_guard **guards,
				   size_t *count)
{
	const void *fdt = get_embedded_dt();
	TEE_Result res = TEE_SUCCESS;
	TEE_Result rc = TEE_SUCCESS;
	size_t n = 0;
	int node = -1;

	*guards = ddr_guards;
	*count = 0;

	if (!fdt)
		return TEE_ERROR_BAD_STATE;

	while (true) {
		node = fdt_node_offset_by_prop_value(fdt, node, "device_type",
						     "memory",
						     sizeof("memory"));
		if (node == -FDT_ERR_NOTFOUND)
			break;
		if (node < 0) {
			if (!res)
				res = TEE_ERROR_BAD_STATE;
			break;
		}
		if (!(fdt_get_status(fdt, node) & DT_STATUS_OK_SEC))
			continue;

		rc = add_node_guards(fdt, node, &n);
		if (rc) {
			EMSG("XPU: DRAM node %s not guarded: %#" PRIx32,
			     fdt_get_name(fdt, node, NULL), rc);
			if (!res)
				res = rc;
		}
	}

	if (!n && !res)
		res = TEE_ERROR_ITEM_NOT_FOUND;

	*count = n;

	return res;
}
