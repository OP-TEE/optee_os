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
#include <xpu_target.h>

/* The most DRAM windows that can be guarded */
#define DDR_GUARDS_MAX		4

static struct xpu4_guard ddr_guards[DDR_GUARDS_MAX];

/*
 * Read a reg address or size of one or two cells. A DRAM window can be larger
 * than 4 GiB, which fdt_get_reg_props_by_index() does not accept as a size.
 */
static uint64_t read_cells(const fdt32_t *cell, int n)
{
	uint64_t val = 0;

	while (n--)
		val = (val << 32) | fdt32_to_cpu(*cell++);

	return val;
}

static TEE_Result add_node_guards(const void *fdt, int node, size_t *count)
{
	const fdt32_t *reg = NULL;
	size_t tuple_len = 0;
	int addr_cells = 0;
	int size_cells = 0;
	int parent = 0;
	int len = 0;
	size_t i = 0;

	reg = fdt_getprop(fdt, node, "reg", &len);
	if (!reg)
		return TEE_ERROR_BAD_STATE;

	parent = fdt_parent_offset(fdt, node);
	if (parent < 0)
		return TEE_ERROR_BAD_STATE;

	addr_cells = fdt_address_cells(fdt, parent);
	size_cells = fdt_size_cells(fdt, parent);
	if (addr_cells < 1 || addr_cells > 2 ||
	    size_cells < 1 || size_cells > 2)
		return TEE_ERROR_BAD_STATE;

	/* A reg that is not a whole number of windows is malformed */
	tuple_len = (addr_cells + size_cells) * sizeof(fdt32_t);
	if (!len || (size_t)len % tuple_len)
		return TEE_ERROR_BAD_STATE;

	for (i = 0; i < (size_t)len / tuple_len; i++) {
		const fdt32_t *tuple = reg + i * (addr_cells + size_cells);
		paddr_t base = read_cells(tuple, addr_cells);
		size_t size = read_cells(tuple + addr_cells, size_cells);

		if (*count == ARRAY_SIZE(ddr_guards)) {
			EMSG("XPU: no room to guard DRAM %#" PRIxPA "+%#zx",
			     base, size);
			return TEE_ERROR_OUT_OF_MEMORY;
		}

		ddr_guards[*count].start = base;
		ddr_guards[*count].size = size;
		ddr_guards[*count].mpu_start = ddr_mpu_addr(base);
		(*count)++;
	}

	return TEE_SUCCESS;
}

/*
 * The DRAM is what the memory nodes of the embedded DT that are not disabled
 * describe. A node that cannot be read or does not fit fails the lookup, as
 * the DRAM in it would be left unguarded.
 */
TEE_Result qcom_xpu_get_ddr_guards(const struct xpu4_guard **guards,
				   size_t *count)
{
	const void *fdt = get_embedded_dt();
	TEE_Result res = TEE_SUCCESS;
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
		if (node < 0)
			return TEE_ERROR_BAD_STATE;
		if (fdt_get_status(fdt, node) == DT_STATUS_DISABLED)
			continue;

		res = add_node_guards(fdt, node, &n);
		if (res) {
			EMSG("XPU: DRAM node %s: %#" PRIx32,
			     fdt_get_name(fdt, node, NULL), res);
			return res;
		}
	}

	if (!n)
		return TEE_ERROR_ITEM_NOT_FOUND;

	*count = n;

	return TEE_SUCCESS;
}
