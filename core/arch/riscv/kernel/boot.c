// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2023 Andes Technology Corporation
 * Copyright 2022-2023 NXP
 */

#include <assert.h>
#include <compiler.h>
#include <config.h>
#include <console.h>
#include <keep.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <kernel/linker.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/thread.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <mm/tee_mm.h>
#include <mm/tee_pager.h>
#include <platform_config.h>
#include <riscv.h>
#include <sbi.h>
#include <stdio.h>
#include <trace.h>
#include <util.h>

#define PADDR_INVALID               ULONG_MAX

paddr_t start_addr;
unsigned long boot_args[4];

uint32_t sem_cpu_sync[CFG_TEE_CORE_NB_CORE];

#ifdef CFG_DT
struct dt_descriptor {
	void *blob;
};

static struct dt_descriptor external_dt __nex_bss;
#endif

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

#if defined(CFG_DT)
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

	if (!IS_ENABLED(CFG_EXTERNAL_DT))
		return TEE_SUCCESS;

	if (!external_dt.blob)
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

#ifdef _CFG_USE_DTB_OVERLAY
static int add_dt_overlay_fragment(struct dt_descriptor *dt, int ioffs)
{
	char frag[32];
	int offs;
	int ret;

	snprintf(frag, sizeof(frag), "fragment@%d", dt->frag_id);
	offs = fdt_add_subnode(dt->blob, ioffs, frag);
	if (offs < 0)
		return offs;

	dt->frag_id += 1;

	ret = fdt_setprop_string(dt->blob, offs, "target-path", "/");
	if (ret < 0)
		return -1;

	return fdt_add_subnode(dt->blob, offs, "__overlay__");
}

static int init_dt_overlay(struct dt_descriptor *dt, int __maybe_unused dt_size)
{
	int fragment;

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

static int add_dt_path_subnode(struct dt_descriptor *dt, const char *path,
			       const char *subnode)
{
	int offs;

	offs = fdt_path_offset(dt->blob, path);
	if (offs < 0)
		return -1;
	offs = add_dt_overlay_fragment(dt, offs);
	if (offs < 0)
		return -1;
	offs = fdt_add_subnode(dt->blob, offs, subnode);
	if (offs < 0)
		return -1;
	return offs;
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

static int add_res_mem_dt_node(struct dt_descriptor *dt, const char *name,
			       paddr_t pa, size_t size)
{
	int offs = 0;
	int ret = 0;
	int addr_size = -1;
	int len_size = -1;
	bool found = true;
	char subnode_name[80] = { 0 };

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
			return -1;
		addr_size = fdt_address_cells(dt->blob, offs);
		if (addr_size < 0)
			return -1;
	}

	if (!found) {
		offs = add_dt_path_subnode(dt, "/", "reserved-memory");
		if (offs < 0)
			return -1;
		ret = fdt_setprop_cell(dt->blob, offs, "#address-cells",
				       addr_size);
		if (ret < 0)
			return -1;
		ret = fdt_setprop_cell(dt->blob, offs, "#size-cells", len_size);
		if (ret < 0)
			return -1;
		ret = fdt_setprop(dt->blob, offs, "ranges", NULL, 0);
		if (ret < 0)
			return -1;
	}

	ret = snprintf(subnode_name, sizeof(subnode_name),
		       "%s@%" PRIxPA, name, pa);
	if (ret < 0 || ret >= (int)sizeof(subnode_name))
		DMSG("truncated node \"%s@%" PRIxPA"\"", name, pa);
	offs = fdt_add_subnode(dt->blob, offs, subnode_name);
	if (offs >= 0) {
		uint32_t data[FDT_MAX_NCELLS * 2];

		set_dt_val(data, addr_size, pa);
		set_dt_val(data + addr_size, len_size, size);
		ret = fdt_setprop(dt->blob, offs, "reg", data,
				  sizeof(uint32_t) * (addr_size + len_size));
		if (ret < 0)
			return -1;
		ret = fdt_setprop(dt->blob, offs, "no-map", NULL, 0);
		if (ret < 0)
			return -1;
	} else {
		return -1;
	}
	return 0;
}

static void init_external_dt(unsigned long phys_dt)
{
	struct dt_descriptor *dt = &external_dt;
	void *fdt;
	int ret;

	if (!IS_ENABLED(CFG_EXTERNAL_DT))
		return;

	if (!phys_dt) {
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

	fdt = core_mmu_add_mapping(MEM_AREA_EXT_DT, phys_dt, CFG_DTB_MAX_SIZE);
	if (!fdt)
		panic("Failed to map external DTB");

	dt->blob = fdt;

	ret = init_dt_overlay(dt, CFG_DTB_MAX_SIZE);
	if (ret < 0) {
		EMSG("Device Tree Overlay init fail @ %#lx: error %d", phys_dt,
		     ret);
		panic();
	}

	ret = fdt_open_into(fdt, fdt, CFG_DTB_MAX_SIZE);
	if (ret < 0) {
		EMSG("Invalid Device Tree at %#lx: error %d", phys_dt, ret);
		panic();
	}

	IMSG("Non-secure external DT found");
}

static int mark_tddram_as_reserved(struct dt_descriptor *dt)
{
	return add_res_mem_dt_node(dt, "optee_core", CFG_TDDRAM_START,
				   CFG_TDDRAM_SIZE);
}

static void update_external_dt(void)
{
	struct dt_descriptor *dt = &external_dt;

	if (!IS_ENABLED(CFG_EXTERNAL_DT))
		return;

	if (!dt->blob)
		return;

	if (mark_tddram_as_reserved(dt))
		panic("Failed to config secure memory");
}
#else /*CFG_DT*/
void *get_external_dt(void)
{
	return NULL;
}

static void init_external_dt(unsigned long phys_dt __unused)
{
}

static void update_external_dt(void)
{
}
#endif /*!CFG_DT*/

void init_sec_mon(unsigned long nsec_entry __maybe_unused)
{
	assert(nsec_entry == PADDR_INVALID);
	/* Do nothing as we don't have a secure monitor */
}

#ifdef CFG_RISCV_S_MODE
static void start_secondary_cores(void)
{
	size_t i = 0;
	size_t pos = get_core_pos();

	for (i = 0; i < CFG_TEE_CORE_NB_CORE; i++)
		if (i != pos && IS_ENABLED(CFG_RISCV_SBI) &&
		    sbi_boot_hart(i, start_addr, i))
			EMSG("Error starting secondary hart %zu", i);
}
#endif

static void init_runtime(void)
{
	malloc_add_pool(__heap1_start, __heap1_end - __heap1_start);

	IMSG_RAW("\n");
}

void init_tee_runtime(void)
{
	core_mmu_init_ta_ram();
	call_preinitcalls();
	call_initcalls();
}

static void init_primary(unsigned long nsec_entry)
{
	thread_init_core_local_stacks();

	/*
	 * Mask asynchronous exceptions before switch to the thread vector
	 * as the thread handler requires those to be masked while
	 * executing with the temporary stack. The thread subsystem also
	 * asserts that the foreign interrupts are blocked when using most of
	 * its functions.
	 */
	thread_set_exceptions(THREAD_EXCP_ALL);

	init_runtime();
	thread_init_boot_thread();
	thread_init_primary();
	thread_init_per_cpu();
	init_sec_mon(nsec_entry);
}

/* May be overridden in plat-$(PLATFORM)/main.c */
__weak void plat_primary_init_early(void)
{
}

/* May be overridden in plat-$(PLATFORM)/main.c */
__weak void main_init_plic(void)
{
}

/* May be overridden in plat-$(PLATFORM)/main.c */
__weak void main_secondary_init_plic(void)
{
}

void boot_init_primary_early(unsigned long pageable_part __unused,
			     unsigned long nsec_entry __unused)
{
	unsigned long e = PADDR_INVALID;

	init_primary(e);
}

void boot_init_primary_late(unsigned long fdt __unused,
			    unsigned long tos_fw_config __unused)
{
	init_external_dt(fdt);
	update_external_dt();

	IMSG("OP-TEE version: %s", core_v_str);
	if (IS_ENABLED(CFG_WARN_INSECURE)) {
		IMSG("WARNING: This OP-TEE configuration might be insecure!");
		IMSG("WARNING: Please check https://optee.readthedocs.io/en/latest/architecture/porting_guidelines.html");
	}
	IMSG("Primary CPU initializing");
	main_init_plic();
	init_tee_runtime();
	call_finalcalls();
	IMSG("Primary CPU initialized");

#ifdef CFG_RISCV_S_MODE
	start_secondary_cores();
#endif
}

static void init_secondary_helper(unsigned long nsec_entry)
{
	size_t pos = get_core_pos();

	IMSG("Secondary CPU %zu initializing", pos);

	/*
	 * Mask asynchronous exceptions before switch to the thread vector
	 * as the thread handler requires those to be masked while
	 * executing with the temporary stack. The thread subsystem also
	 * asserts that the foreign interrupts are blocked when using most of
	 * its functions.
	 */
	thread_set_exceptions(THREAD_EXCP_ALL);

	thread_init_per_cpu();
	init_sec_mon(nsec_entry);
	main_secondary_init_plic();

	IMSG("Secondary CPU %zu initialized", pos);
}

void boot_init_secondary(unsigned long nsec_entry __unused)
{
	init_secondary_helper(PADDR_INVALID);
}
