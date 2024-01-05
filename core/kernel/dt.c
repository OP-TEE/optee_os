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

	pbase = fdt_reg_base_address(fdt, offs);
	if (pbase == DT_INFO_INVALID_REG)
		return -1;
	sz = fdt_reg_size(fdt, offs);
	if (sz == DT_INFO_INVALID_REG_SIZE)
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

paddr_t fdt_reg_base_address(const void *fdt, int offs)
{
	const void *reg;
	int ncells;
	int len;
	int parent;

	parent = fdt_parent_offset(fdt, offs);
	if (parent < 0)
		return DT_INFO_INVALID_REG;

	reg = fdt_getprop(fdt, offs, "reg", &len);
	if (!reg)
		return DT_INFO_INVALID_REG;

	ncells = fdt_address_cells(fdt, parent);
	if (ncells < 0)
		return DT_INFO_INVALID_REG;

	return fdt_read_paddr(reg, ncells);
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

size_t fdt_reg_size(const void *fdt, int offs)
{
	const uint32_t *reg;
	int n;
	int len;
	int parent;

	parent = fdt_parent_offset(fdt, offs);
	if (parent < 0)
		return DT_INFO_INVALID_REG_SIZE;

	reg = (const uint32_t *)fdt_getprop(fdt, offs, "reg", &len);
	if (!reg)
		return DT_INFO_INVALID_REG_SIZE;

	n = fdt_address_cells(fdt, parent);
	if (n < 1 || n > 2)
		return DT_INFO_INVALID_REG_SIZE;

	reg += n;

	n = fdt_size_cells(fdt, parent);
	if (n < 1 || n > 2)
		return DT_INFO_INVALID_REG_SIZE;

	return fdt_read_size(reg, n);
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
	const fdt32_t *cuint;

	dinfo.reg = fdt_reg_base_address(fdt, offs);
	dinfo.reg_size = fdt_reg_size(fdt, offs);

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

int fdt_get_reg_props_by_index(const void *fdt, int node, int index,
			       paddr_t *base, size_t *size)
{
	const fdt32_t *prop = NULL;
	int parent = 0;
	int len = 0;
	int address_cells = 0;
	int size_cells = 0;
	int cell = 0;

	parent = fdt_parent_offset(fdt, node);
	if (parent < 0)
		return parent;

	address_cells = fdt_address_cells(fdt, parent);
	if (address_cells < 0)
		return address_cells;

	size_cells = fdt_size_cells(fdt, parent);
	if (size_cells < 0)
		return size_cells;

	cell = index * (address_cells + size_cells);

	prop = fdt_getprop(fdt, node, "reg", &len);
	if (!prop)
		return len;

	if (((cell + address_cells + size_cells) * (int)sizeof(uint32_t)) > len)
		return -FDT_ERR_BADVALUE;

	if (base) {
		*base = fdt_read_paddr(&prop[cell], address_cells);
		if (*base == DT_INFO_INVALID_REG)
			return -FDT_ERR_BADVALUE;
	}

	if (size) {
		*size = fdt_read_size(&prop[cell + address_cells], size_cells);
		if (*size == DT_INFO_INVALID_REG_SIZE)
			return -FDT_ERR_BADVALUE;
	}

	return 0;
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

	return fdt;
}

void *get_secure_dt(void)
{
	void *fdt = get_embedded_dt();

	if (!fdt && IS_ENABLED(CFG_MAP_EXT_DT_SECURE))
		fdt = get_external_dt();

	return fdt;
}

#if defined(CFG_EMBED_DTB)
void *get_embedded_dt(void)
{
	static bool checked;

	assert(cpu_mmu_enabled());

	if (!checked) {
		IMSG("Embedded DTB found");

		if (fdt_check_header(embedded_secure_dtb))
			panic("Invalid embedded DTB");

		checked = true;
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
