// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 */

#include <assert.h>
#include <config.h>
#include <initcall.h>
#include <kernel/dt.h>
#include <kernel/dt_driver.h>
#include <kernel/interrupt.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <stdio.h>
#include <string.h>
#include <trace.h>

static struct dt_descriptor external_dt __nex_bss;

#if defined(CFG_CORE_FFA)
static void *manifest_dt __nex_bss;
#endif

const struct dt_driver *dt_find_compatible_driver(const void *fdt, int offs)
{
	const struct dt_device_match *dm;
	const struct dt_driver *drv;

	for_each_dt_driver(drv) {
		for (dm = drv->match_table; dm; dm++) {
			if (!dm->compatible) {
				break;
			}
			if (!fdt_node_check_compatible(fdt, offs,
						       dm->compatible)) {
				return drv;
			}
		}
	}

	return NULL;
}

bool dt_have_prop(const void *fdt, int offs, const char *propname)
{
	const void *prop;

	prop = fdt_getprop(fdt, offs, propname, NULL);

	return prop;
}

int dt_disable_status(void *fdt, int node)
{
	const char *prop = NULL;
	int len = 0;

	prop = fdt_getprop(fdt, node, "status", &len);
	if (!prop) {
		if (fdt_setprop_string(fdt, node, "status", "disabled"))
			return -1;
	} else {
		/*
		 * Status is there, modify it.
		 * Ask to set "disabled" value to the property. The value
		 * will be automatically truncated with "len" size by the
		 * fdt_setprop_inplace function.
		 * Setting a value different from "ok" or "okay" will disable
		 * the property.
		 * Setting a truncated value of "disabled" with the original
		 * property "len" is preferred to not increase the DT size and
		 * losing time in recalculating the overall DT offsets.
		 * If original length of the status property is larger than
		 * "disabled", the property will start with "disabled" and be
		 * completed with the rest of the original property.
		 */
		if (fdt_setprop_inplace(fdt, node, "status", "disabled", len))
			return -1;
	}

	return 0;
}

int dt_enable_secure_status(void *fdt, int node)
{
	if (dt_disable_status(fdt, node)) {
		EMSG("Unable to disable Normal Status");
		return -1;
	}

	if (fdt_setprop_string(fdt, node, "secure-status", "okay"))
		return -1;

	return 0;
}

int dt_map_dev(const void *fdt, int offs, vaddr_t *base, size_t *size,
	       enum dt_map_dev_directive mapping)
{
	enum teecore_memtypes mtype;
	paddr_t pbase;
	vaddr_t vbase;
	size_t sz;
	int st;

	assert(cpu_mmu_enabled());

	st = fdt_get_status(fdt, offs);
	if (st == DT_STATUS_DISABLED)
		return -1;

	if (fdt_reg_info(fdt, offs, &pbase, &sz))
		return -1;

	switch (mapping) {
	case DT_MAP_AUTO:
		if ((st & DT_STATUS_OK_SEC) && !(st & DT_STATUS_OK_NSEC))
			mtype = MEM_AREA_IO_SEC;
		else
			mtype = MEM_AREA_IO_NSEC;
		break;
	case DT_MAP_SECURE:
		mtype = MEM_AREA_IO_SEC;
		break;
	case DT_MAP_NON_SECURE:
		mtype = MEM_AREA_IO_NSEC;
		break;
	default:
		panic("Invalid mapping specified");
		break;
	}

	/* Check if we have a mapping, create one if needed */
	vbase = (vaddr_t)core_mmu_add_mapping(mtype, pbase, sz);
	if (!vbase) {
		EMSG("Failed to map %zu bytes at PA 0x%"PRIxPA,
		     (size_t)sz, pbase);
		return -1;
	}

	*base = vbase;
	*size = sz;
	return 0;
}

/* Read a physical address (n=1 or 2 cells) */
static paddr_t fdt_read_paddr(const uint32_t *cell, int n)
{
	paddr_t addr;

	if (n < 1 || n > 2)
		goto bad;

	addr = fdt32_to_cpu(*cell);
	cell++;
	if (n == 2) {
#ifdef ARM32
		if (addr) {
			/* High order 32 bits can't be nonzero */
			goto bad;
		}
		addr = fdt32_to_cpu(*cell);
#else
		addr = (addr << 32) | fdt32_to_cpu(*cell);
#endif
	}

	return addr;
bad:
	return DT_INFO_INVALID_REG;

}

static size_t fdt_read_size(const uint32_t *cell, int n)
{
	uint32_t sz = 0;

	sz = fdt32_to_cpu(*cell);
	if (n == 2) {
		if (sz)
			return DT_INFO_INVALID_REG_SIZE;

		cell++;
		sz = fdt32_to_cpu(*cell);
	}

	return sz;
}

int fdt_get_reg_props_by_index(const void *fdt, int offs, int index,
			       paddr_t *base, size_t *size)
{
	const fdt32_t *reg = NULL;
	int addr_ncells = 0;
	int size_ncells = 0;
	int cell_offset = 0;
	int parent = 0;
	int len = 0;

	if (index < 0)
		return -FDT_ERR_BADOFFSET;

	reg = (const uint32_t *)fdt_getprop(fdt, offs, "reg", &len);
	if (!reg)
		return -FDT_ERR_NOTFOUND;

	if (fdt_find_cached_parent_reg_cells(fdt, offs, &addr_ncells,
					     &size_ncells) != 0) {
		parent = fdt_parent_offset(fdt, offs);
		if (parent < 0)
			return -FDT_ERR_NOTFOUND;

		addr_ncells = fdt_address_cells(fdt, parent);
		if (addr_ncells < 0)
			return -FDT_ERR_NOTFOUND;

		size_ncells = fdt_size_cells(fdt, parent);
		if (size_ncells < 0)
			return -FDT_ERR_NOTFOUND;
	}

	cell_offset = index * (addr_ncells + size_ncells);

	if ((size_t)len < (cell_offset + addr_ncells) * sizeof(*reg))
		return -FDT_ERR_BADSTRUCTURE;

	if (base) {
		*base = fdt_read_paddr(reg + cell_offset, addr_ncells);
		if (*base == DT_INFO_INVALID_REG)
			return -FDT_ERR_NOTFOUND;
	}

	if (size) {
		if ((size_t)len <
		    (cell_offset + addr_ncells + size_ncells) * sizeof(*reg))
			return -FDT_ERR_BADSTRUCTURE;

		*size = fdt_read_size(reg + cell_offset + addr_ncells,
				      size_ncells);
		if (*size == DT_INFO_INVALID_REG_SIZE)
			return -FDT_ERR_NOTFOUND;
	}

	return 0;
}

int fdt_reg_info(const void *fdt, int offs, paddr_t *base, size_t *size)
{
	return fdt_get_reg_props_by_index(fdt, offs, 0, base, size);
}

paddr_t fdt_reg_base_address(const void *fdt, int offs)
{
	paddr_t base = 0;

	if (fdt_reg_info(fdt, offs, &base, NULL))
		return DT_INFO_INVALID_REG;

	return base;
}

size_t fdt_reg_size(const void *fdt, int offs)
{
	size_t size = 0;

	if (fdt_reg_info(fdt, offs, NULL, &size))
		return DT_INFO_INVALID_REG_SIZE;

	return size;
}

static bool is_okay(const char *st, int len)
{
	return !strncmp(st, "ok", len) || !strncmp(st, "okay", len);
}

int fdt_get_status(const void *fdt, int offs)
{
	const char *prop;
	int st = 0;
	int len;

	prop = fdt_getprop(fdt, offs, "status", &len);
	if (!prop || is_okay(prop, len)) {
		/* If status is not specified, it defaults to "okay" */
		st |= DT_STATUS_OK_NSEC;
	}

	prop = fdt_getprop(fdt, offs, "secure-status", &len);
	if (!prop) {
		/*
		 * When secure-status is not specified it defaults to the same
		 * value as status
		 */
		if (st & DT_STATUS_OK_NSEC)
			st |= DT_STATUS_OK_SEC;
	} else {
		if (is_okay(prop, len))
			st |= DT_STATUS_OK_SEC;
	}

	return st;
}

void fdt_fill_device_info(const void *fdt, struct dt_node_info *info, int offs)
{
	struct dt_node_info dinfo = {
		.reg = DT_INFO_INVALID_REG,
		.reg_size = DT_INFO_INVALID_REG_SIZE,
		.clock = DT_INFO_INVALID_CLOCK,
		.reset = DT_INFO_INVALID_RESET,
		.interrupt = DT_INFO_INVALID_INTERRUPT,
	};
	const fdt32_t *cuint = NULL;

	/* Intentionally discard fdt_reg_info() return value */
	fdt_reg_info(fdt, offs, &dinfo.reg, &dinfo.reg_size);

	cuint = fdt_getprop(fdt, offs, "clocks", NULL);
	if (cuint) {
		cuint++;
		dinfo.clock = (int)fdt32_to_cpu(*cuint);
	}

	cuint = fdt_getprop(fdt, offs, "resets", NULL);
	if (cuint) {
		cuint++;
		dinfo.reset = (int)fdt32_to_cpu(*cuint);
	}

	dinfo.interrupt = dt_get_irq_type_prio(fdt, offs, &dinfo.type,
					       &dinfo.prio);

	dinfo.status = fdt_get_status(fdt, offs);

	*info = dinfo;
}

int fdt_read_uint32_array(const void *fdt, int node, const char *prop_name,
			  uint32_t *array, size_t count)
{
	const fdt32_t *cuint = NULL;
	int len = 0;
	uint32_t i = 0;

	cuint = fdt_getprop(fdt, node, prop_name, &len);
	if (!cuint)
		return len;

	if ((uint32_t)len != (count * sizeof(uint32_t)))
		return -FDT_ERR_BADLAYOUT;

	for (i = 0; i < ((uint32_t)len / sizeof(uint32_t)); i++) {
		*array = fdt32_to_cpu(*cuint);
		array++;
		cuint++;
	}

	return 0;
}

int fdt_read_uint32_index(const void *fdt, int node, const char *prop_name,
			  int index, uint32_t *value)
{
	const fdt32_t *cuint = NULL;
	int len = 0;

	cuint = fdt_getprop(fdt, node, prop_name, &len);
	if (!cuint)
		return len;

	if ((uint32_t)len < (sizeof(uint32_t) * (index + 1)))
		return -FDT_ERR_BADLAYOUT;

	*value = fdt32_to_cpu(cuint[index]);

	return 0;
}

int fdt_read_uint32(const void *fdt, int node, const char *prop_name,
		    uint32_t *value)
{
	return fdt_read_uint32_array(fdt, node, prop_name, value, 1);
}

uint32_t fdt_read_uint32_default(const void *fdt, int node,
				 const char *prop_name, uint32_t dflt_value)
{
	uint32_t ret = dflt_value;

	fdt_read_uint32_index(fdt, node, prop_name, 0, &ret);

	return ret;
}

int fdt_get_reg_props_by_name(const void *fdt, int node, const char *name,
			      paddr_t *base, size_t *size)
{
	int index = 0;

	index = fdt_stringlist_search(fdt, node, "reg-names", name);
	if (index < 0)
		return index;

	return fdt_get_reg_props_by_index(fdt, node, index, base, size);
}

int dt_getprop_as_number(const void *fdt, int nodeoffset, const char *name,
			 uint64_t *num)
{
	const void *prop = NULL;
	int len = 0;

	prop = fdt_getprop(fdt, nodeoffset, name, &len);
	if (!prop)
		return len;

	switch (len) {
	case sizeof(uint32_t):
		*num = fdt32_ld(prop);
		return 0;
	case sizeof(uint64_t):
		*num = fdt64_ld(prop);
		return 0;
	default:
		return -FDT_ERR_BADVALUE;
	}
}

void *get_dt(void)
{
	void *fdt = get_embedded_dt();

	if (!fdt)
		fdt = get_external_dt();

	if (!fdt)
		fdt = get_manifest_dt();

	return fdt;
}

void *get_secure_dt(void)
{
	void *fdt = get_embedded_dt();

	if (!fdt && IS_ENABLED(CFG_MAP_EXT_DT_SECURE))
		fdt = get_external_dt();

	if (!fdt)
		fdt = get_manifest_dt();

	return fdt;
}

#if defined(CFG_EMBED_DTB)
#ifdef CFG_DT_CACHED_NODE_INFO
/*
 * struct cached_node - Cached information of a DT node
 *
 * @node_offset: Offset of the node in @cached_node_info_fdt
 * @parent_offset: Offset of @node_offset parent node
 * @address_cells: #address-cells property value of the parent node or 0
 * @size_cells: #size-cells property value of the parent node or 0
 * @phandle: Phandle associated to the node or 0 if none
 */
struct cached_node {
	int node_offset;
	int parent_offset;
	int8_t address_cells;
	int8_t size_cells;
	uint32_t phandle;
};

/*
 * struct dt_node_cache - Reference to cached information of DT nodes
 *
 * @array: Array of the cached node
 * @count: Number of initialized cells in @array
 * @alloced_count: Number of allocated cells in @array
 * @fdt: Reference to the FDT for which node information are cached
 */
struct dt_node_cache {
	struct cached_node *array;
	size_t count;
	size_t alloced_count;
	const void *fdt;
};

static struct dt_node_cache *dt_node_cache;

static bool fdt_node_info_are_cached(const void *fdt)
{
	return dt_node_cache && dt_node_cache->fdt == fdt;
}

static struct cached_node *find_cached_parent_node(const void *fdt,
						   int node_offset)
{
	struct cached_node *cell = NULL;
	size_t n = 0;

	if (!fdt_node_info_are_cached(fdt))
		return NULL;

	for (n = 0; n < dt_node_cache->count; n++)
		if (dt_node_cache->array[n].node_offset == node_offset)
			cell = dt_node_cache->array + n;

	return cell;
}

int fdt_find_cached_parent_node(const void *fdt, int node_offset,
				int *parent_offset)
{
	struct cached_node *cell = NULL;

	cell = find_cached_parent_node(fdt, node_offset);
	if (!cell)
		return -FDT_ERR_NOTFOUND;

	*parent_offset = cell->parent_offset;

	return 0;
}

int fdt_find_cached_parent_reg_cells(const void *fdt, int node_offset,
				     int *address_cells, int *size_cells)
{
	struct cached_node *cell = NULL;
	int rc = 0;

	cell = find_cached_parent_node(fdt, node_offset);
	if (!cell)
		return -FDT_ERR_NOTFOUND;

	if (address_cells) {
		if (cell->address_cells >= 0)
			*address_cells = cell->address_cells;
		else
			rc = -FDT_ERR_NOTFOUND;
	}

	if (size_cells) {
		if (cell->size_cells >= 0)
			*size_cells = cell->size_cells;
		else
			rc = -FDT_ERR_NOTFOUND;
	}

	return rc;
}

int fdt_find_cached_node_phandle(const void *fdt, uint32_t phandle,
				 int *node_offset)
{
	struct cached_node *cell = NULL;
	size_t n = 0;

	if (!fdt_node_info_are_cached(fdt))
		return -FDT_ERR_NOTFOUND;

	for (n = 0; n < dt_node_cache->count; n++)
		if (dt_node_cache->array[n].phandle == phandle)
			cell = dt_node_cache->array + n;

	if (!cell)
		return -FDT_ERR_NOTFOUND;

	*node_offset = cell->node_offset;

	return 0;
}

static TEE_Result realloc_cached_node_array(void)
{
	assert(dt_node_cache);

	if (dt_node_cache->count + 1 > dt_node_cache->alloced_count) {
		size_t new_count = dt_node_cache->alloced_count * 2;
		struct cached_node *new = NULL;

		if (!new_count)
			new_count = 4;

		new = realloc(dt_node_cache->array,
			      sizeof(*dt_node_cache->array) * new_count);
		if (!new)
			return TEE_ERROR_OUT_OF_MEMORY;

		dt_node_cache->array = new;
		dt_node_cache->alloced_count = new_count;
	}

	return TEE_SUCCESS;
}

static TEE_Result add_cached_node(int parent_offset,
				  int node_offset, int address_cells,
				  int size_cells)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	res = realloc_cached_node_array();
	if (res)
		return res;

	dt_node_cache->array[dt_node_cache->count] = (struct cached_node){
		.node_offset = node_offset,
		.parent_offset = parent_offset,
		.address_cells = address_cells,
		.size_cells = size_cells,
		.phandle = fdt_get_phandle(dt_node_cache->fdt, node_offset),
	};

	dt_node_cache->count++;

	return TEE_SUCCESS;
}

static TEE_Result add_cached_node_subtree(int node_offset)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	const fdt32_t *cuint = NULL;
	int subnode_offset = 0;
	int8_t addr_cells = -1;
	int8_t size_cells = -1;

	cuint = fdt_getprop(dt_node_cache->fdt, node_offset, "#address-cells",
			    NULL);
	if (cuint)
		addr_cells = (int)fdt32_to_cpu(*cuint);

	cuint = fdt_getprop(dt_node_cache->fdt, node_offset, "#size-cells",
			    NULL);
	if (cuint)
		size_cells = (int)fdt32_to_cpu(*cuint);

	fdt_for_each_subnode(subnode_offset, dt_node_cache->fdt, node_offset) {
		res = add_cached_node(node_offset, subnode_offset, addr_cells,
				      size_cells);
		if (res)
			return res;

		res = add_cached_node_subtree(subnode_offset);
		if (res)
			return res;
	}

	return TEE_SUCCESS;
}

static TEE_Result release_node_cache_info(void)
{
	if (dt_node_cache) {
		free(dt_node_cache->array);
		free(dt_node_cache);
		dt_node_cache = NULL;
	}

	return TEE_SUCCESS;
}

release_init_resource(release_node_cache_info);

static void init_node_cache_info(const void *fdt)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	assert(!dt_node_cache);

	dt_node_cache = calloc(1, sizeof(*dt_node_cache));
	if (dt_node_cache) {
		dt_node_cache->fdt = fdt;
		res = add_cached_node_subtree(0);
	} else {
		res = TEE_ERROR_OUT_OF_MEMORY;
	}

	if (res) {
		EMSG("Error %#"PRIx32", disable DT cached info", res);
		release_node_cache_info();
	}
}
#else
static void init_node_cache_info(const void *fdt __unused)
{
}
#endif /* CFG_DT_CACHED_NODE_INFO */

void *get_embedded_dt(void)
{
	static bool checked;

	assert(cpu_mmu_enabled());

	if (!checked) {
		IMSG("Embedded DTB found");

		if (fdt_check_header(embedded_secure_dtb))
			panic("Invalid embedded DTB");

		checked = true;

		init_node_cache_info(embedded_secure_dtb);
	}

	return embedded_secure_dtb;
}
#else
void *get_embedded_dt(void)
{
	return NULL;
}
#endif /*CFG_EMBED_DTB*/

#ifdef _CFG_USE_DTB_OVERLAY
static int add_dt_overlay_fragment(struct dt_descriptor *dt, int ioffs)
{
	char frag[32] = { };
	int offs = 0;
	int ret = 0;

	ret = snprintf(frag, sizeof(frag), "fragment@%d", dt->frag_id);
	if (ret < 0 || (size_t)ret >= sizeof(frag))
		return -1;

	offs = fdt_add_subnode(dt->blob, ioffs, frag);
	if (offs < 0)
		return offs;

	dt->frag_id += 1;

	ret = fdt_setprop_string(dt->blob, offs, "target-path", "/");
	if (ret < 0)
		return ret;

	return fdt_add_subnode(dt->blob, offs, "__overlay__");
}

static int init_dt_overlay(struct dt_descriptor *dt, int __maybe_unused dt_size)
{
	int fragment = 0;

	if (IS_ENABLED(CFG_EXTERNAL_DTB_OVERLAY)) {
		if (!fdt_check_header(dt->blob)) {
			fdt_for_each_subnode(fragment, dt->blob, 0)
				dt->frag_id += 1;
			return 0;
		}
	}

	return fdt_create_empty_tree(dt->blob, dt_size);
}
#else
static int add_dt_overlay_fragment(struct dt_descriptor *dt __unused, int offs)
{
	return offs;
}

static int init_dt_overlay(struct dt_descriptor *dt __unused,
			   int dt_size __unused)
{
	return 0;
}
#endif /* _CFG_USE_DTB_OVERLAY */

struct dt_descriptor *get_external_dt_desc(void)
{
	if (!IS_ENABLED(CFG_EXTERNAL_DT))
		return NULL;

	return &external_dt;
}

void init_external_dt(unsigned long phys_dt, size_t dt_sz)
{
	struct dt_descriptor *dt = &external_dt;
	int ret = 0;
	enum teecore_memtypes mtype = MEM_AREA_MAXTYPE;

	if (!IS_ENABLED(CFG_EXTERNAL_DT))
		return;

	if (!phys_dt || !dt_sz) {
		/*
		 * No need to panic as we're not using the DT in OP-TEE
		 * yet, we're only adding some nodes for normal world use.
		 * This makes the switch to using DT easier as we can boot
		 * a newer OP-TEE with older boot loaders. Once we start to
		 * initialize devices based on DT we'll likely panic
		 * instead of returning here.
		 */
		IMSG("No non-secure external DT");
		return;
	}

	mtype = core_mmu_get_type_by_pa(phys_dt);
	if (mtype == MEM_AREA_MAXTYPE) {
		/* Map the DTB if it is not yet mapped */
		dt->blob = core_mmu_add_mapping(MEM_AREA_EXT_DT, phys_dt,
						dt_sz);
		if (!dt->blob)
			panic("Failed to map external DTB");
	} else {
		/* Get the DTB address if already mapped in a memory area */
		dt->blob = phys_to_virt(phys_dt, mtype, dt_sz);
		if (!dt->blob) {
			EMSG("Failed to get a mapped external DTB for PA %#lx",
			     phys_dt);
			panic();
		}
	}

	ret = init_dt_overlay(dt, dt_sz);
	if (ret < 0) {
		EMSG("Device Tree Overlay init fail @ %#lx: error %d", phys_dt,
		     ret);
		panic();
	}

	ret = fdt_open_into(dt->blob, dt->blob, dt_sz);
	if (ret < 0) {
		EMSG("Invalid Device Tree at %#lx: error %d", phys_dt, ret);
		panic();
	}

	IMSG("Non-secure external DT found");
}

void *get_external_dt(void)
{
	if (!IS_ENABLED(CFG_EXTERNAL_DT))
		return NULL;

	assert(cpu_mmu_enabled());
	return external_dt.blob;
}

static TEE_Result release_external_dt(void)
{
	int ret = 0;
	paddr_t pa_dt = 0;

	if (!IS_ENABLED(CFG_EXTERNAL_DT))
		return TEE_SUCCESS;

	if (!external_dt.blob)
		return TEE_SUCCESS;

	pa_dt = virt_to_phys(external_dt.blob);
	/*
	 * Skip packing and un-mapping operations if the external DTB is mapped
	 * in a different memory area
	 */
	if (core_mmu_get_type_by_pa(pa_dt) != MEM_AREA_EXT_DT)
		return TEE_SUCCESS;

	ret = fdt_pack(external_dt.blob);
	if (ret < 0) {
		EMSG("Failed to pack Device Tree at 0x%" PRIxPA ": error %d",
		     virt_to_phys(external_dt.blob), ret);
		panic();
	}

	if (core_mmu_remove_mapping(MEM_AREA_EXT_DT, external_dt.blob,
				    CFG_DTB_MAX_SIZE))
		panic("Failed to remove temporary Device Tree mapping");

	/* External DTB no more reached, reset pointer to invalid */
	external_dt.blob = NULL;

	return TEE_SUCCESS;
}

boot_final(release_external_dt);

int add_dt_path_subnode(struct dt_descriptor *dt, const char *path,
			const char *subnode)
{
	int offs = 0;

	offs = fdt_path_offset(dt->blob, path);
	if (offs < 0)
		return offs;
	offs = add_dt_overlay_fragment(dt, offs);
	if (offs < 0)
		return offs;
	return fdt_add_subnode(dt->blob, offs, subnode);
}

static void set_dt_val(void *data, uint32_t cell_size, uint64_t val)
{
	if (cell_size == 1) {
		fdt32_t v = cpu_to_fdt32((uint32_t)val);

		memcpy(data, &v, sizeof(v));
	} else {
		fdt64_t v = cpu_to_fdt64(val);

		memcpy(data, &v, sizeof(v));
	}
}

int add_res_mem_dt_node(struct dt_descriptor *dt, const char *name,
			paddr_t pa, size_t size)
{
	int offs = 0;
	int ret = 0;
	int addr_size = -1;
	int len_size = -1;
	bool found = true;
	char subnode_name[80] = { };

	offs = fdt_path_offset(dt->blob, "/reserved-memory");

	if (offs < 0) {
		found = false;
		offs = 0;
	}

	if (IS_ENABLED2(_CFG_USE_DTB_OVERLAY)) {
		len_size = sizeof(paddr_t) / sizeof(uint32_t);
		addr_size = sizeof(paddr_t) / sizeof(uint32_t);
	} else {
		len_size = fdt_size_cells(dt->blob, offs);
		if (len_size < 0)
			return len_size;
		addr_size = fdt_address_cells(dt->blob, offs);
		if (addr_size < 0)
			return addr_size;
	}

	if (!found) {
		offs = add_dt_path_subnode(dt, "/", "reserved-memory");
		if (offs < 0)
			return offs;
		ret = fdt_setprop_cell(dt->blob, offs, "#address-cells",
				       addr_size);
		if (ret < 0)
			return ret;
		ret = fdt_setprop_cell(dt->blob, offs, "#size-cells", len_size);
		if (ret < 0)
			return ret;
		ret = fdt_setprop(dt->blob, offs, "ranges", NULL, 0);
		if (ret < 0)
			return ret;
	}

	ret = snprintf(subnode_name, sizeof(subnode_name),
		       "%s@%" PRIxPA, name, pa);
	if (ret < 0 || ret >= (int)sizeof(subnode_name))
		DMSG("truncated node \"%s@%" PRIxPA"\"", name, pa);
	offs = fdt_add_subnode(dt->blob, offs, subnode_name);
	if (offs >= 0) {
		uint32_t data[FDT_MAX_NCELLS * 2] = { };

		set_dt_val(data, addr_size, pa);
		set_dt_val(data + addr_size, len_size, size);
		ret = fdt_setprop(dt->blob, offs, "reg", data,
				  sizeof(uint32_t) * (addr_size + len_size));
		if (ret < 0)
			return ret;
		ret = fdt_setprop(dt->blob, offs, "no-map", NULL, 0);
		if (ret < 0)
			return ret;
	} else {
		return offs;
	}
	return 0;
}

#if defined(CFG_CORE_FFA)
void init_manifest_dt(void *fdt)
{
	manifest_dt = fdt;
}

void reinit_manifest_dt(void)
{
	paddr_t pa = (unsigned long)manifest_dt;
	void *fdt = NULL;
	int ret = 0;

	if (!pa) {
		EMSG("No manifest DT found");
		return;
	}

	fdt = core_mmu_add_mapping(MEM_AREA_MANIFEST_DT, pa, CFG_DTB_MAX_SIZE);
	if (!fdt)
		panic("Failed to map manifest DT");

	manifest_dt = fdt;

	ret = fdt_check_full(fdt, CFG_DTB_MAX_SIZE);
	if (ret < 0) {
		EMSG("Invalid manifest Device Tree at %#lx: error %d", pa, ret);
		panic();
	}

	IMSG("manifest DT found");
}

void *get_manifest_dt(void)
{
	return manifest_dt;
}

static TEE_Result release_manifest_dt(void)
{
	if (!manifest_dt)
		return TEE_SUCCESS;

	if (core_mmu_remove_mapping(MEM_AREA_MANIFEST_DT, manifest_dt,
				    CFG_DTB_MAX_SIZE))
		panic("Failed to remove temporary manifest DT mapping");
	manifest_dt = NULL;

	return TEE_SUCCESS;
}

boot_final(release_manifest_dt);
#else
void init_manifest_dt(void *fdt __unused)
{
}

void reinit_manifest_dt(void)
{
}

void *get_manifest_dt(void)
{
	return NULL;
}
#endif /*CFG_CORE_FFA*/
