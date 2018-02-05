// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015-2018, Linaro Limited
 */

#include <arm.h>
#include <assert.h>
#include <compiler.h>
#include <console.h>
#include <crypto/crypto.h>
#include <inttypes.h>
#include <keep.h>
#include <kernel/asan.h>
#include <kernel/generic_boot.h>
#include <kernel/linker.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/tee_misc.h>
#include <kernel/thread.h>
#include <malloc.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <mm/tee_mm.h>
#include <mm/tee_mmu.h>
#include <mm/tee_pager.h>
#include <sm/psci.h>
#include <sm/tee_mon.h>
#include <stdio.h>
#include <trace.h>
#include <utee_defines.h>
#include <util.h>

#include <platform_config.h>

#if !defined(CFG_WITH_ARM_TRUSTED_FW)
#include <sm/sm.h>
#endif

#if defined(CFG_WITH_VFP)
#include <kernel/vfp.h>
#endif

#if defined(CFG_DT)
#include <libfdt.h>
#endif

/*
 * In this file we're using unsigned long to represent physical pointers as
 * they are received in a single register when OP-TEE is initially entered.
 * This limits 32-bit systems to only use make use of the lower 32 bits
 * of a physical address for initial parameters.
 *
 * 64-bit systems on the other hand can use full 64-bit physical pointers.
 */
#define PADDR_INVALID		ULONG_MAX

#if defined(CFG_BOOT_SECONDARY_REQUEST)
struct ns_entry_context {
	uintptr_t entry_point;
	uintptr_t context_id;
};
struct ns_entry_context ns_entry_contexts[CFG_TEE_CORE_NB_CORE];
static uint32_t spin_table[CFG_TEE_CORE_NB_CORE];
#endif

#ifdef CFG_BOOT_SYNC_CPU
/*
 * Array used when booting, to synchronize cpu.
 * When 0, the cpu has not started.
 * When 1, it has started
 */
uint32_t sem_cpu_sync[CFG_TEE_CORE_NB_CORE];
KEEP_PAGER(sem_cpu_sync);
#endif

#ifdef CFG_DT
struct dt_descriptor {
	void *blob;
	int frag_id;
};

static struct dt_descriptor external_dt;
#endif

#ifdef CFG_SECONDARY_INIT_CNTFRQ
static uint32_t cntfrq;
#endif

/* May be overridden in plat-$(PLATFORM)/main.c */
__weak void plat_cpu_reset_late(void)
{
}
KEEP_PAGER(plat_cpu_reset_late);

/* May be overridden in plat-$(PLATFORM)/main.c */
__weak void main_init_gic(void)
{
}

/* May be overridden in plat-$(PLATFORM)/main.c */
__weak void main_secondary_init_gic(void)
{
}

#if defined(CFG_WITH_ARM_TRUSTED_FW)
void init_sec_mon(unsigned long nsec_entry __maybe_unused)
{
	assert(nsec_entry == PADDR_INVALID);
	/* Do nothing as we don't have a secure monitor */
}
#else
/* May be overridden in plat-$(PLATFORM)/main.c */
__weak void init_sec_mon(unsigned long nsec_entry)
{
	struct sm_nsec_ctx *nsec_ctx;

	assert(nsec_entry != PADDR_INVALID);

	/* Initialize secure monitor */
	nsec_ctx = sm_get_nsec_ctx();
	nsec_ctx->mon_lr = nsec_entry;
	nsec_ctx->mon_spsr = CPSR_MODE_SVC | CPSR_I;

}
#endif

#if defined(CFG_WITH_ARM_TRUSTED_FW)
static void init_vfp_nsec(void)
{
}
#else
static void init_vfp_nsec(void)
{
	/* Normal world can use CP10 and CP11 (SIMD/VFP) */
	write_nsacr(read_nsacr() | NSACR_CP10 | NSACR_CP11);
}
#endif

#if defined(CFG_WITH_VFP)

#ifdef ARM32
static void init_vfp_sec(void)
{
	uint32_t cpacr = read_cpacr();

	/*
	 * Enable Advanced SIMD functionality.
	 * Enable use of D16-D31 of the Floating-point Extension register
	 * file.
	 */
	cpacr &= ~(CPACR_ASEDIS | CPACR_D32DIS);
	/*
	 * Enable usage of CP10 and CP11 (SIMD/VFP) (both kernel and user
	 * mode.
	 */
	cpacr |= CPACR_CP(10, CPACR_CP_ACCESS_FULL);
	cpacr |= CPACR_CP(11, CPACR_CP_ACCESS_FULL);
	write_cpacr(cpacr);
}
#endif /* ARM32 */

#ifdef ARM64
static void init_vfp_sec(void)
{
	/* Not using VFP until thread_kernel_enable_vfp() */
	vfp_disable();
}
#endif /* ARM64 */

#else /* CFG_WITH_VFP */

static void init_vfp_sec(void)
{
	/* Not using VFP */
}
#endif

#ifdef CFG_SECONDARY_INIT_CNTFRQ
static void primary_save_cntfrq(void)
{
	assert(cntfrq == 0);

	/*
	 * CNTFRQ should be initialized on the primary CPU by a
	 * previous boot stage
	 */
	cntfrq = read_cntfrq();
}

static void secondary_init_cntfrq(void)
{
	assert(cntfrq != 0);
	write_cntfrq(cntfrq);
}
#else /* CFG_SECONDARY_INIT_CNTFRQ */
static void primary_save_cntfrq(void)
{
}

static void secondary_init_cntfrq(void)
{
}
#endif

#ifdef CFG_CORE_SANITIZE_KADDRESS
static void init_run_constructors(void)
{
	const vaddr_t *ctor;

	for (ctor = &__ctor_list; ctor < &__ctor_end; ctor++)
		((void (*)(void))(*ctor))();
}

static void init_asan(void)
{

	/*
	 * CFG_ASAN_SHADOW_OFFSET is also supplied as
	 * -fasan-shadow-offset=$(CFG_ASAN_SHADOW_OFFSET) to the compiler.
	 * Since all the needed values to calculate the value of
	 * CFG_ASAN_SHADOW_OFFSET isn't available in to make we need to
	 * calculate it in advance and hard code it into the platform
	 * conf.mk. Here where we have all the needed values we double
	 * check that the compiler is supplied the correct value.
	 */

#define __ASAN_SHADOW_START \
	ROUNDUP(TEE_RAM_VA_START + (TEE_RAM_VA_SIZE * 8) / 9 - 8, 8)
	assert(__ASAN_SHADOW_START == (vaddr_t)&__asan_shadow_start);
#define __CFG_ASAN_SHADOW_OFFSET \
	(__ASAN_SHADOW_START - (TEE_RAM_VA_START / 8))
	COMPILE_TIME_ASSERT(CFG_ASAN_SHADOW_OFFSET == __CFG_ASAN_SHADOW_OFFSET);
#undef __ASAN_SHADOW_START
#undef __CFG_ASAN_SHADOW_OFFSET

	/*
	 * Assign area covered by the shadow area, everything from start up
	 * to the beginning of the shadow area.
	 */
	asan_set_shadowed((void *)TEE_TEXT_VA_START, &__asan_shadow_start);

	/*
	 * Add access to areas that aren't opened automatically by a
	 * constructor.
	 */
	asan_tag_access(&__ctor_list, &__ctor_end);
	asan_tag_access(__rodata_start, __rodata_end);
#ifdef CFG_WITH_PAGER
	asan_tag_access(__pageable_start, __pageable_end);
#endif /*CFG_WITH_PAGER*/
	asan_tag_access(__nozi_start, __nozi_end);
	asan_tag_access(__exidx_start, __exidx_end);
	asan_tag_access(__extab_start, __extab_end);

	init_run_constructors();

	/* Everything is tagged correctly, let's start address sanitizing. */
	asan_start();
}
#else /*CFG_CORE_SANITIZE_KADDRESS*/
static void init_asan(void)
{
}
#endif /*CFG_CORE_SANITIZE_KADDRESS*/

#ifdef CFG_WITH_PAGER

#ifdef CFG_CORE_SANITIZE_KADDRESS
static void carve_out_asan_mem(tee_mm_pool_t *pool)
{
	const size_t s = pool->hi - pool->lo;
	tee_mm_entry_t *mm;
	paddr_t apa = ASAN_MAP_PA;
	size_t asz = ASAN_MAP_SZ;

	if (core_is_buffer_outside(apa, asz, pool->lo, s))
		return;

	/* Reserve the shadow area */
	if (!core_is_buffer_inside(apa, asz, pool->lo, s)) {
		if (apa < pool->lo) {
			/*
			 * ASAN buffer is overlapping with the beginning of
			 * the pool.
			 */
			asz -= pool->lo - apa;
			apa = pool->lo;
		} else {
			/*
			 * ASAN buffer is overlapping with the end of the
			 * pool.
			 */
			asz = pool->hi - apa;
		}
	}
	mm = tee_mm_alloc2(pool, apa, asz);
	assert(mm);
}
#else
static void carve_out_asan_mem(tee_mm_pool_t *pool __unused)
{
}
#endif

static void print_pager_pool_size(void)
{
	struct tee_pager_stats __maybe_unused stats;

	tee_pager_get_stats(&stats);
	IMSG("Pager pool size: %zukB",
		stats.npages_all * SMALL_PAGE_SIZE / 1024);
}

static void init_vcore(tee_mm_pool_t *mm_vcore)
{
	const vaddr_t begin = TEE_RAM_VA_START;
	vaddr_t end = TEE_RAM_VA_START + TEE_RAM_VA_SIZE;

#ifdef CFG_CORE_SANITIZE_KADDRESS
	/* Carve out asan memory, flat maped after core memory */
	if (end > ASAN_SHADOW_PA)
		end = ASAN_MAP_PA;
#endif

	if (!tee_mm_init(mm_vcore, begin, end, SMALL_PAGE_SHIFT,
			 TEE_MM_POOL_NO_FLAGS))
		panic("tee_mm_vcore init failed");
}

static void init_runtime(unsigned long pageable_part)
{
	size_t n;
	size_t init_size = (size_t)__init_size;
	size_t pageable_size = __pageable_end - __pageable_start;
	size_t hash_size = (pageable_size / SMALL_PAGE_SIZE) *
			   TEE_SHA256_HASH_SIZE;
	tee_mm_entry_t *mm;
	uint8_t *paged_store;
	uint8_t *hashes;

	assert(pageable_size % SMALL_PAGE_SIZE == 0);
	assert(hash_size == (size_t)__tmp_hashes_size);

	/*
	 * This needs to be initialized early to support address lookup
	 * in MEM_AREA_TEE_RAM
	 */
	tee_pager_early_init();

	thread_init_boot_thread();

	init_asan();

	malloc_add_pool(__heap1_start, __heap1_end - __heap1_start);
	malloc_add_pool(__heap2_start, __heap2_end - __heap2_start);

	hashes = malloc(hash_size);
	IMSG_RAW("\n");
	IMSG("Pager is enabled. Hashes: %zu bytes", hash_size);
	assert(hashes);
	asan_memcpy_unchecked(hashes, __tmp_hashes_start, hash_size);

	/*
	 * Need tee_mm_sec_ddr initialized to be able to allocate secure
	 * DDR below.
	 */
	teecore_init_ta_ram();

	carve_out_asan_mem(&tee_mm_sec_ddr);

	mm = tee_mm_alloc(&tee_mm_sec_ddr, pageable_size);
	assert(mm);
	paged_store = phys_to_virt(tee_mm_get_smem(mm), MEM_AREA_TA_RAM);
	/*
	 * Load pageable part in the dedicated allocated area:
	 * - Move pageable non-init part into pageable area. Note bootloader
	 *   may have loaded it anywhere in TA RAM hence use memmove().
	 * - Copy pageable init part from current location into pageable area.
	 */
	memmove(paged_store + init_size,
		phys_to_virt(pageable_part,
			     core_mmu_get_type_by_pa(pageable_part)),
		__pageable_part_end - __pageable_part_start);
	asan_memcpy_unchecked(paged_store, __init_start, init_size);

	/* Check that hashes of what's in pageable area is OK */
	DMSG("Checking hashes of pageable area");
	for (n = 0; (n * SMALL_PAGE_SIZE) < pageable_size; n++) {
		const uint8_t *hash = hashes + n * TEE_SHA256_HASH_SIZE;
		const uint8_t *page = paged_store + n * SMALL_PAGE_SIZE;
		TEE_Result res;

		DMSG("hash pg_idx %zu hash %p page %p", n, hash, page);
		res = hash_sha256_check(hash, page, SMALL_PAGE_SIZE);
		if (res != TEE_SUCCESS) {
			EMSG("Hash failed for page %zu at %p: res 0x%x",
			     n, page, res);
			panic();
		}
	}

	/*
	 * Assert prepaged init sections are page aligned so that nothing
	 * trails uninited at the end of the premapped init area.
	 */
	assert(!(init_size & SMALL_PAGE_MASK));

	/*
	 * Initialize the virtual memory pool used for main_mmu_l2_ttb which
	 * is supplied to tee_pager_init() below.
	 */
	init_vcore(&tee_mm_vcore);

	/*
	 * Assign alias area for pager end of the small page block the rest
	 * of the binary is loaded into. We're taking more than needed, but
	 * we're guaranteed to not need more than the physical amount of
	 * TZSRAM.
	 */
	mm = tee_mm_alloc2(&tee_mm_vcore,
		(vaddr_t)tee_mm_vcore.hi - TZSRAM_SIZE, TZSRAM_SIZE);
	assert(mm);
	tee_pager_set_alias_area(mm);

	/*
	 * Claim virtual memory which isn't paged.
	 * Linear memory (flat map core memory) ends there.
	 */
	mm = tee_mm_alloc2(&tee_mm_vcore, VCORE_UNPG_RX_PA,
			   (vaddr_t)(__pageable_start - VCORE_UNPG_RX_PA));
	assert(mm);

	/*
	 * Allocate virtual memory for the pageable area and let the pager
	 * take charge of all the pages already assigned to that memory.
	 */
	mm = tee_mm_alloc2(&tee_mm_vcore, (vaddr_t)__pageable_start,
			   pageable_size);
	assert(mm);
	tee_pager_add_core_area(tee_mm_get_smem(mm), tee_mm_get_bytes(mm),
				TEE_MATTR_PRX, paged_store, hashes);

	tee_pager_add_pages((vaddr_t)__pageable_start,
			init_size / SMALL_PAGE_SIZE, false);
	tee_pager_add_pages((vaddr_t)__pageable_start + init_size,
			(pageable_size - init_size) / SMALL_PAGE_SIZE, true);

	/*
	 * There may be physical pages in TZSRAM before the core load address.
	 * These pages can be added to the physical pages pool of the pager.
	 * This setup may happen when a the secure bootloader runs in TZRAM
	 * and its memory can be reused by OP-TEE once boot stages complete.
	 */
	tee_pager_add_pages(tee_mm_vcore.lo,
			(VCORE_UNPG_RX_PA - tee_mm_vcore.lo) / SMALL_PAGE_SIZE,
			true);

	print_pager_pool_size();
}
#else

static void init_runtime(unsigned long pageable_part __unused)
{
	thread_init_boot_thread();

	init_asan();
	malloc_add_pool(__heap1_start, __heap1_end - __heap1_start);

#ifdef CFG_VIRTUALIZATION
	nex_malloc_add_pool(__nex_heap_start, __nex_heap_end -
					      __nex_heap_start);
#endif

	/*
	 * Initialized at this stage in the pager version of this function
	 * above
	 */
	teecore_init_ta_ram();
	IMSG_RAW("\n");
}
#endif

void *get_dt(void)
{
	void *fdt = get_embedded_dt();

	if (!fdt)
		fdt = get_external_dt();

	return fdt;
}

#if defined(CFG_EMBED_DTB)
void *get_embedded_dt(void)
{
	static bool checked;

	assert(cpu_mmu_enabled());

	if (!checked) {
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
	assert(cpu_mmu_enabled());
	return external_dt.blob;
}

static void release_external_dt(void)
{
	/* External DTB no more reached, reset pointer to invalid */
	external_dt.blob = NULL;
}

#ifdef CFG_EXTERNAL_DTB_OVERLAY
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
	int ret;

	ret = fdt_check_header(dt->blob);
	if (!ret) {
		fdt_for_each_subnode(fragment, dt->blob, 0)
			dt->frag_id += 1;
		return ret;
	}

#ifdef CFG_DT_ADDR
	return fdt_create_empty_tree(dt->blob, dt_size);
#else
	return -1;
#endif
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
#endif /* CFG_EXTERNAL_DTB_OVERLAY */

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

static int add_optee_dt_node(struct dt_descriptor *dt)
{
	int offs;
	int ret;

	if (fdt_path_offset(dt->blob, "/firmware/optee") >= 0) {
		DMSG("OP-TEE Device Tree node already exists!\n");
		return 0;
	}

	offs = fdt_path_offset(dt->blob, "/firmware");
	if (offs < 0) {
		offs = add_dt_path_subnode(dt, "/", "firmware");
		if (offs < 0)
			return -1;
	}

	offs = fdt_add_subnode(dt->blob, offs, "optee");
	if (offs < 0)
		return -1;

	ret = fdt_setprop_string(dt->blob, offs, "compatible",
				 "linaro,optee-tz");
	if (ret < 0)
		return -1;
	ret = fdt_setprop_string(dt->blob, offs, "method", "smc");
	if (ret < 0)
		return -1;
	return 0;
}

#ifdef CFG_PSCI_ARM32
static int append_psci_compatible(void *fdt, int offs, const char *str)
{
	return fdt_appendprop(fdt, offs, "compatible", str, strlen(str) + 1);
}

static int dt_add_psci_node(struct dt_descriptor *dt)
{
	int offs;

	if (fdt_path_offset(dt->blob, "/psci") >= 0) {
		DMSG("PSCI Device Tree node already exists!\n");
		return 0;
	}

	offs = add_dt_path_subnode(dt, "/", "psci");
	if (offs < 0)
		return -1;
	if (append_psci_compatible(dt->blob, offs, "arm,psci-1.0"))
		return -1;
	if (append_psci_compatible(dt->blob, offs, "arm,psci-0.2"))
		return -1;
	if (append_psci_compatible(dt->blob, offs, "arm,psci"))
		return -1;
	if (fdt_setprop_string(dt->blob, offs, "method", "smc"))
		return -1;
	if (fdt_setprop_u32(dt->blob, offs, "cpu_suspend", PSCI_CPU_SUSPEND))
		return -1;
	if (fdt_setprop_u32(dt->blob, offs, "cpu_off", PSCI_CPU_OFF))
		return -1;
	if (fdt_setprop_u32(dt->blob, offs, "cpu_on", PSCI_CPU_ON))
		return -1;
	if (fdt_setprop_u32(dt->blob, offs, "sys_poweroff", PSCI_SYSTEM_OFF))
		return -1;
	if (fdt_setprop_u32(dt->blob, offs, "sys_reset", PSCI_SYSTEM_RESET))
		return -1;
	return 0;
}

static int check_node_compat_prefix(struct dt_descriptor *dt, int offs,
				    const char *prefix)
{
	const size_t prefix_len = strlen(prefix);
	size_t l;
	int plen;
	const char *prop;

	prop = fdt_getprop(dt->blob, offs, "compatible", &plen);
	if (!prop)
		return -1;

	while (plen > 0) {
		if (memcmp(prop, prefix, prefix_len) == 0)
			return 0; /* match */

		l = strlen(prop) + 1;
		prop += l;
		plen -= l;
	}

	return -1;
}

static int dt_add_psci_cpu_enable_methods(struct dt_descriptor *dt)
{
	int offs = 0;

	while (1) {
		offs = fdt_next_node(dt->blob, offs, NULL);
		if (offs < 0)
			break;
		if (fdt_getprop(dt->blob, offs, "enable-method", NULL))
			continue; /* already set */
		if (check_node_compat_prefix(dt, offs, "arm,cortex-a"))
			continue; /* no compatible */
		if (fdt_setprop_string(dt->blob, offs, "enable-method", "psci"))
			return -1;
		/* Need to restart scanning as offsets may have changed */
		offs = 0;
	}
	return 0;
}

static int config_psci(struct dt_descriptor *dt)
{
	if (dt_add_psci_node(dt))
		return -1;
	return dt_add_psci_cpu_enable_methods(dt);
}
#else
static int config_psci(struct dt_descriptor *dt __unused)
{
	return 0;
}
#endif /*CFG_PSCI_ARM32*/

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

static uint64_t get_dt_val_and_advance(const void *data, size_t *offs,
				       uint32_t cell_size)
{
	uint64_t rv;

	if (cell_size == 1) {
		uint32_t v;

		memcpy(&v, (const uint8_t *)data + *offs, sizeof(v));
		*offs += sizeof(v);
		rv = fdt32_to_cpu(v);
	} else {
		uint64_t v;

		memcpy(&v, (const uint8_t *)data + *offs, sizeof(v));
		*offs += sizeof(v);
		rv = fdt64_to_cpu(v);
	}

	return rv;
}

static int add_res_mem_dt_node(struct dt_descriptor *dt, const char *name,
			       paddr_t pa, size_t size)
{
	int offs;
	int ret;
	int addr_size = 2;
	int len_size = 2;
	char subnode_name[80];

	offs = fdt_path_offset(dt->blob, "/reserved-memory");
	if (offs >= 0) {
		addr_size = fdt_address_cells(dt->blob, offs);
		if (addr_size < 0)
			return -1;
		len_size = fdt_size_cells(dt->blob, offs);
		if (len_size < 0)
			return -1;
	} else {
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

	snprintf(subnode_name, sizeof(subnode_name),
		 "%s@0x%" PRIxPA, name, pa);
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

static struct core_mmu_phys_mem *get_memory(void *fdt, size_t *nelems)
{
	int offs;
	int addr_size;
	int len_size;
	size_t prop_len;
	const uint8_t *prop;
	size_t prop_offs;
	size_t n;
	struct core_mmu_phys_mem *mem;

	offs = fdt_subnode_offset(fdt, 0, "memory");
	if (offs < 0)
		return NULL;

	prop = fdt_getprop(fdt, offs, "reg", &addr_size);
	if (!prop)
		return NULL;

	prop_len = addr_size;
	addr_size = fdt_address_cells(fdt, 0);
	if (addr_size < 0)
		return NULL;

	len_size = fdt_size_cells(fdt, 0);
	if (len_size < 0)
		return NULL;

	for (n = 0, prop_offs = 0; prop_offs < prop_len; n++) {
		get_dt_val_and_advance(prop, &prop_offs, addr_size);
		if (prop_offs >= prop_len) {
			n--;
			break;
		}
		get_dt_val_and_advance(prop, &prop_offs, len_size);
	}

	if (!n)
		return NULL;

	*nelems = n;
	mem = calloc(n, sizeof(*mem));
	if (!mem)
		panic();

	for (n = 0, prop_offs = 0; n < *nelems; n++) {
		mem[n].type = MEM_AREA_RAM_NSEC;
		mem[n].addr = get_dt_val_and_advance(prop, &prop_offs,
						     addr_size);
		mem[n].size = get_dt_val_and_advance(prop, &prop_offs,
						     len_size);
	}

	return mem;
}

static int mark_static_shm_as_reserved(struct dt_descriptor *dt)
{
	vaddr_t shm_start;
	vaddr_t shm_end;

	core_mmu_get_mem_by_type(MEM_AREA_NSEC_SHM, &shm_start, &shm_end);
	if (shm_start != shm_end)
		return add_res_mem_dt_node(dt, "optee",
					   virt_to_phys((void *)shm_start),
					   shm_end - shm_start);

	DMSG("No SHM configured");
	return -1;
}

static void init_external_dt(unsigned long phys_dt)
{
	struct dt_descriptor *dt = &external_dt;
	void *fdt;
	int ret;

	if (!phys_dt) {
		EMSG("Device Tree missing");
		/*
		 * No need to panic as we're not using the DT in OP-TEE
		 * yet, we're only adding some nodes for normal world use.
		 * This makes the switch to using DT easier as we can boot
		 * a newer OP-TEE with older boot loaders. Once we start to
		 * initialize devices based on DT we'll likely panic
		 * instead of returning here.
		 */
		return;
	}

	if (!core_mmu_add_mapping(MEM_AREA_IO_NSEC, phys_dt, CFG_DTB_MAX_SIZE))
		panic("Failed to map external DTB");

	fdt = phys_to_virt(phys_dt, MEM_AREA_IO_NSEC);
	if (!fdt)
		panic();

	dt->blob = fdt;

	ret = init_dt_overlay(dt, CFG_DTB_MAX_SIZE);
	if (ret < 0) {
		EMSG("Device Tree Overlay init fail @ 0x%" PRIxPA ": error %d",
		     phys_dt, ret);
		panic();
	}

	ret = fdt_open_into(fdt, fdt, CFG_DTB_MAX_SIZE);
	if (ret < 0) {
		EMSG("Invalid Device Tree at 0x%" PRIxPA ": error %d",
		     phys_dt, ret);
		panic();
	}
}

static void update_external_dt(void)
{
	struct dt_descriptor *dt = &external_dt;
	int ret;

	if (!dt->blob)
		return;

	if (add_optee_dt_node(dt))
		panic("Failed to add OP-TEE Device Tree node");

	if (config_psci(dt))
		panic("Failed to config PSCI");

	if (mark_static_shm_as_reserved(dt))
		panic("Failed to config non-secure memory");

	ret = fdt_pack(dt->blob);
	if (ret < 0) {
		EMSG("Failed to pack Device Tree at 0x%" PRIxPA ": error %d",
		     virt_to_phys(dt->blob), ret);
		panic();
	}
}
#else /*CFG_DT*/
void *get_external_dt(void)
{
	return NULL;
}

static void release_external_dt(void)
{
}

static void init_external_dt(unsigned long phys_dt __unused)
{
}

static void update_external_dt(void)
{
}

static struct core_mmu_phys_mem *get_memory(void *fdt __unused,
					    size_t *nelems __unused)
{
	return NULL;
}
#endif /*!CFG_DT*/

static void discover_nsec_memory(void)
{
	struct core_mmu_phys_mem *mem;
	size_t nelems;
	void *fdt = get_dt();

	if (fdt) {
		mem = get_memory(fdt, &nelems);
		if (mem) {
			core_mmu_set_discovered_nsec_ddr(mem, nelems);
			return;
		}

		DMSG("No non-secure memory found in FDT");
	}

	nelems = phys_ddr_overall_end - phys_ddr_overall_begin;
	if (!nelems)
		return;

	/* Platform cannot define nsec_ddr && overall_ddr */
	assert(phys_nsec_ddr_begin == phys_nsec_ddr_end);

	mem = calloc(nelems, sizeof(*mem));
	if (!mem)
		panic();

	memcpy(mem, phys_ddr_overall_begin, sizeof(*mem) * nelems);
	core_mmu_set_discovered_nsec_ddr(mem, nelems);
}

static void init_primary_helper(unsigned long pageable_part,
				unsigned long nsec_entry, unsigned long fdt)
{
	/*
	 * Mask asynchronous exceptions before switch to the thread vector
	 * as the thread handler requires those to be masked while
	 * executing with the temporary stack. The thread subsystem also
	 * asserts that the foreign interrupts are blocked when using most of
	 * its functions.
	 */
	thread_set_exceptions(THREAD_EXCP_ALL);
	primary_save_cntfrq();
	init_vfp_sec();
	init_runtime(pageable_part);

	thread_init_primary(generic_boot_get_handlers());
	thread_init_per_cpu();
	init_sec_mon(nsec_entry);
	init_external_dt(fdt);
	discover_nsec_memory();
	update_external_dt();
	configure_console_from_dt();

	IMSG("OP-TEE version: %s", core_v_str);

	main_init_gic();
	init_vfp_nsec();
	if (init_teecore() != TEE_SUCCESS)
		panic();
	release_external_dt();
	DMSG("Primary CPU switching to normal world boot\n");
}

/* What this function is using is needed each time another CPU is started */
KEEP_PAGER(generic_boot_get_handlers);

static void init_secondary_helper(unsigned long nsec_entry)
{
	/*
	 * Mask asynchronous exceptions before switch to the thread vector
	 * as the thread handler requires those to be masked while
	 * executing with the temporary stack. The thread subsystem also
	 * asserts that the foreign interrupts are blocked when using most of
	 * its functions.
	 */
	thread_set_exceptions(THREAD_EXCP_ALL);

	secondary_init_cntfrq();
	thread_init_per_cpu();
	init_sec_mon(nsec_entry);
	main_secondary_init_gic();
	init_vfp_sec();
	init_vfp_nsec();

	DMSG("Secondary CPU Switching to normal world boot\n");
}

#if defined(CFG_WITH_ARM_TRUSTED_FW)
struct thread_vector_table *
generic_boot_init_primary(unsigned long pageable_part, unsigned long u __unused,
			  unsigned long fdt)
{
	init_primary_helper(pageable_part, PADDR_INVALID, fdt);
	return &thread_vector_table;
}

unsigned long generic_boot_cpu_on_handler(unsigned long a0 __maybe_unused,
				     unsigned long a1 __unused)
{
	DMSG("cpu %zu: a0 0x%lx", get_core_pos(), a0);
	init_secondary_helper(PADDR_INVALID);
	return 0;
}
#else
void generic_boot_init_primary(unsigned long pageable_part,
			       unsigned long nsec_entry, unsigned long fdt)
{
	init_primary_helper(pageable_part, nsec_entry, fdt);
}

void generic_boot_init_secondary(unsigned long nsec_entry)
{
	init_secondary_helper(nsec_entry);
}
#endif

#if defined(CFG_BOOT_SECONDARY_REQUEST)
void generic_boot_set_core_ns_entry(size_t core_idx, uintptr_t entry,
				    uintptr_t context_id)
{
	ns_entry_contexts[core_idx].entry_point = entry;
	ns_entry_contexts[core_idx].context_id = context_id;
	dsb_ishst();
}

int generic_boot_core_release(size_t core_idx, paddr_t entry)
{
	if (!core_idx || core_idx >= CFG_TEE_CORE_NB_CORE)
		return -1;

	ns_entry_contexts[core_idx].entry_point = entry;
	dmb();
	spin_table[core_idx] = 1;
	dsb();
	sev();

	return 0;
}

/*
 * spin until secondary boot request, then returns with
 * the secondary core entry address.
 */
struct ns_entry_context *generic_boot_core_hpen(void)
{
#ifdef CFG_PSCI_ARM32
	return &ns_entry_contexts[get_core_pos()];
#else
	do {
		wfe();
	} while (!spin_table[get_core_pos()]);
	dmb();
	return &ns_entry_contexts[get_core_pos()];
#endif
}
#endif
