// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <compiler.h>
#include <config.h>
#include <drivers/qcom/xpuv4.h>
#include <kernel/dt.h>
#include <kernel/dt_driver.h>
#include <libfdt.h>
#include <platform_config.h>
#include <stdlib.h>
#include <string.h>
#include <tee_api_types.h>
#include <trace.h>
#include <util.h>
#include <xpu_target.h>

/*
 * A region that an XPU protects. The DT names it by its role, which says
 * what access it gets. It has to be where the image was built to have it:
 * the DT cannot move OP-TEE, and protecting another range would leave the
 * memory of OP-TEE open.
 */
struct xpu_region {
	const char *name;
	paddr_t base;
	size_t size;
	uint32_t read_qad;
	uint32_t write_qad;
	bool enabled;
};

static const struct xpu_region xpu_regions[] = {
	{
		.name = "tzdram",
		.base = CFG_TZDRAM_START,
		.size = CFG_TZDRAM_SIZE,
		.read_qad = TZDRAM_XPU_READ_QAD,
		.write_qad = TZDRAM_XPU_WRITE_QAD,
		.enabled = true,
	},
	{
		/*
		 * The DIAG log buffer only holds data when the log itself
		 * is built in, so protecting it otherwise would lock a
		 * resource group for a region nothing uses.
		 */
		.name = "diag",
		.base = DIAG_BASE,
		.size = DIAG_SIZE,
		.read_qad = DIAG_XPU_READ_QAD,
		.write_qad = DIAG_XPU_WRITE_QAD,
		.enabled = IS_ENABLED(CFG_QCOM_DIAG_LOG),
	},
};

/* The XPUs probed so far, which xpu_protect_region() looks into */
static struct xpu4_instance *xpu_instances;
static size_t xpu_instance_count;

/* The reg of a node: windows of an address and a size of one or two cells */
struct xpu_reg {
	const fdt32_t *cells;
	int addr_cells;
	int size_cells;
	size_t count;
};

/*
 * Read an address or a size of one or two cells. A window of the DRAM can be
 * larger than 4 GiB, which fdt_get_reg_props_by_index() does not accept as a
 * size.
 */
static uint64_t read_cells(const fdt32_t *cell, int n)
{
	uint64_t val = 0;

	while (n--)
		val = (val << 32) | fdt32_to_cpu(*cell++);

	return val;
}

/* The cells of an address and of a size in the properties of a node */
static TEE_Result get_cells(const void *fdt, int node, int *addr_cells,
			    int *size_cells)
{
	int parent = fdt_parent_offset(fdt, node);

	if (parent < 0)
		return TEE_ERROR_BAD_STATE;

	*addr_cells = fdt_address_cells(fdt, parent);
	*size_cells = fdt_size_cells(fdt, parent);
	if (*addr_cells < 1 || *addr_cells > 2 ||
	    *size_cells < 1 || *size_cells > 2)
		return TEE_ERROR_BAD_STATE;

	return TEE_SUCCESS;
}

static TEE_Result get_reg(const void *fdt, int node, struct xpu_reg *reg)
{
	size_t tuple_len = 0;
	int len = 0;

	reg->cells = fdt_getprop(fdt, node, "reg", &len);
	if (!reg->cells ||
	    get_cells(fdt, node, &reg->addr_cells, &reg->size_cells))
		return TEE_ERROR_BAD_STATE;

	/* A reg that is not a whole number of windows is malformed */
	tuple_len = (reg->addr_cells + reg->size_cells) * sizeof(fdt32_t);
	if (!len || (size_t)len % tuple_len)
		return TEE_ERROR_BAD_STATE;

	reg->count = len / tuple_len;

	return TEE_SUCCESS;
}

static void get_window(const struct xpu_reg *reg, size_t idx, paddr_t *base,
		       size_t *size)
{
	const fdt32_t *tuple = reg->cells +
			       idx * (reg->addr_cells + reg->size_cells);

	*base = read_cells(tuple, reg->addr_cells);
	*size = read_cells(tuple + reg->addr_cells, reg->size_cells);
}

/* The resource groups that the node lets OP-TEE allocate from */
static TEE_Result get_rg_window(const void *fdt, int node, unsigned int *start,
				unsigned int *count)
{
	uint32_t rg[2] = { };
	uint32_t end = 0;

	if (fdt_read_uint32_array(fdt, node, "qcom,resource-groups", rg,
				  ARRAY_SIZE(rg)) || !rg[1] ||
	    ADD_OVERFLOW(rg[0], rg[1], &end))
		return TEE_ERROR_BAD_STATE;

	*start = rg[0];
	*count = rg[1];

	return TEE_SUCCESS;
}

/*
 * The memory that the unit guards, from qcom,mpu-ranges: for each range, the
 * address that the unit uses for it, its physical address and its size, in
 * the cells of the parent. A property that cannot be read fails the probe, as
 * the memory would be left open.
 */
static TEE_Result get_guards(const void *fdt, int node,
			     struct xpu4_guard **guards, size_t *count)
{
	struct xpu4_guard *g = NULL;
	const fdt32_t *cell = NULL;
	size_t tuple_cells = 0;
	int addr_cells = 0;
	int size_cells = 0;
	size_t n = 0;
	size_t i = 0;
	int len = 0;

	cell = fdt_getprop(fdt, node, "qcom,mpu-ranges", &len);
	if (!cell || get_cells(fdt, node, &addr_cells, &size_cells))
		return TEE_ERROR_BAD_STATE;

	/* A property that is not a whole number of ranges is malformed */
	tuple_cells = 2 * addr_cells + size_cells;
	if (!len || (size_t)len % (tuple_cells * sizeof(*cell)))
		return TEE_ERROR_BAD_STATE;

	n = (size_t)len / (tuple_cells * sizeof(*cell));
	g = calloc(n, sizeof(*g));
	if (!g)
		return TEE_ERROR_OUT_OF_MEMORY;

	for (i = 0; i < n; i++, cell += tuple_cells) {
		g[i].mpu_start = read_cells(cell, addr_cells);
		g[i].start = read_cells(cell + addr_cells, addr_cells);
		g[i].size = read_cells(cell + 2 * addr_cells, size_cells);
		if (!g[i].size) {
			free(g);
			return TEE_ERROR_BAD_STATE;
		}
	}

	*guards = g;
	*count = n;

	return TEE_SUCCESS;
}

static const struct xpu_region *find_region(const char *name)
{
	size_t i = 0;

	for (i = 0; i < ARRAY_SIZE(xpu_regions); i++)
		if (!strcmp(xpu_regions[i].name, name))
			return &xpu_regions[i];

	return NULL;
}

/*
 * Protect the regions that the node lists. One that cannot be programmed is
 * logged and the others are still protected. One that is not where the image
 * has it, or whose role is unknown, fails the probe.
 */
static TEE_Result protect_regions(const void *fdt, int node)
{
	const fdt32_t *list = NULL;
	size_t i = 0;
	int len = 0;

	list = fdt_getprop(fdt, node, "memory-region", &len);
	if (!list || (size_t)len % sizeof(*list))
		return TEE_ERROR_BAD_STATE;

	for (i = 0; i < (size_t)len / sizeof(*list); i++) {
		const struct xpu_region *r = NULL;
		struct xpu_reg reg = { };
		const char *name = NULL;
		TEE_Result res = TEE_ERROR_GENERIC;
		paddr_t base = 0;
		size_t size = 0;
		int region = 0;

		name = fdt_stringlist_get(fdt, node, "memory-region-names", i,
					  NULL);
		region = fdt_node_offset_by_phandle(fdt,
						    fdt32_to_cpu(list[i]));
		if (!name || region < 0 || get_reg(fdt, region, &reg))
			return TEE_ERROR_BAD_STATE;

		r = find_region(name);
		if (!r) {
			EMSG("XPU: unknown region %s", name);
			return TEE_ERROR_BAD_STATE;
		}
		if (!r->enabled)
			continue;

		get_window(&reg, 0, &base, &size);
		if (base != r->base || size != r->size) {
			EMSG("XPU: %s is %#" PRIxPA "+%#zx in the DT, %#" PRIxPA
			     "+%#zx in the image", r->name, base, size,
			     r->base, r->size);
			return TEE_ERROR_BAD_STATE;
		}

		res = xpu_protect_region(base, size, r->read_qad, r->write_qad);
		if (res)
			EMSG("XPU: %s protection failed: %#" PRIx32, r->name,
			     res);
		else
			DMSG("XPU: %s %#" PRIxPA "+%#zx protected", r->name,
			     base, size);
	}

	return TEE_SUCCESS;
}

static TEE_Result xpu_probe(const void *fdt, int node,
			    const void *compat_data __unused)
{
	struct xpu4_instance *tmp = NULL;
	struct xpu4_guard *guards = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	unsigned int rg_start = 0;
	unsigned int rg_count = 0;
	size_t guard_count = 0;
	vaddr_t va = 0;
	paddr_t base = 0;
	size_t size = 0;

	/*
	 * The registers are secure only. xpu_protect_region() reaches them
	 * through this mapping.
	 */
	if (dt_map_dev(fdt, node, &va, &size, DT_MAP_SECURE) < 0 ||
	    fdt_reg_info(fdt, node, &base, &size))
		return TEE_ERROR_GENERIC;

	res = get_rg_window(fdt, node, &rg_start, &rg_count);
	if (res) {
		EMSG("XPU: no usable resource groups for %s",
		     fdt_get_name(fdt, node, NULL));
		return res;
	}

	res = get_guards(fdt, node, &guards, &guard_count);
	if (res) {
		EMSG("XPU: no usable qcom,mpu-ranges for %s: %#" PRIx32,
		     fdt_get_name(fdt, node, NULL), res);
		return res;
	}

	tmp = realloc(xpu_instances,
		      (xpu_instance_count + 1) * sizeof(*xpu_instances));
	if (!tmp) {
		free(guards);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	xpu_instances = tmp;
	xpu_instances[xpu_instance_count++] = (struct xpu4_instance){
		.base = base,
		.map_size = size,
		.guards = guards,
		.guard_count = guard_count,
		.rg_start = rg_start,
		.rg_count = rg_count,
	};
	xpu4_register_instances(xpu_instances, xpu_instance_count);

	return protect_regions(fdt, node);
}

static const struct dt_device_match xpu_match_table[] = {
	{ .compatible = "qcom,xpu4" },
	{ }
};

DEFINE_DT_DRIVER(xpu_dt_driver) = {
	.name = "qcom-xpu4",
	.type = DT_DRIVER_NOTYPE,
	.match_table = xpu_match_table,
	.probe = xpu_probe,
};
