// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015-2020, Linaro Limited
 */

#include <arm.h>
#include <assert.h>
#include <compiler.h>
#include <config.h>
#include <console.h>
#include <crypto/crypto.h>
#include <initcall.h>
#include <inttypes.h>
#include <keep.h>
#include <kernel/asan.h>
#include <kernel/boot.h>
#include <kernel/linker.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/tee_misc.h>
#include <kernel/thread.h>
#include <kernel/tpm.h>
#include <libfdt.h>
#include <malloc.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <mm/fobj.h>
#include <mm/tee_mm.h>
#include <mm/tee_pager.h>
#include <sm/psci.h>
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
DECLARE_KEEP_PAGER(sem_cpu_sync);
#endif

#ifdef CFG_DT
struct dt_descriptor {
	void *blob;
	int frag_id;
};

static struct dt_descriptor external_dt __nex_bss;
#endif

#ifdef CFG_SECONDARY_INIT_CNTFRQ
static uint32_t cntfrq;
#endif

/* May be overridden in plat-$(PLATFORM)/main.c */
__weak void plat_primary_init_early(void)
{
}
DECLARE_KEEP_PAGER(plat_primary_init_early);

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
	if (nsec_entry & 1)
		nsec_ctx->mon_spsr |= CPSR_T;
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
	const vaddr_t begin = VCORE_START_VA;
	vaddr_t end = begin + TEE_RAM_VA_SIZE;

#ifdef CFG_CORE_SANITIZE_KADDRESS
	/* Carve out asan memory, flat maped after core memory */
	if (end > ASAN_SHADOW_PA)
		end = ASAN_MAP_PA;
#endif

	if (!tee_mm_init(mm_vcore, begin, end, SMALL_PAGE_SHIFT,
			 TEE_MM_POOL_NO_FLAGS))
		panic("tee_mm_vcore init failed");
}

/*
 * With CFG_CORE_ASLR=y the init part is relocated very early during boot.
 * The init part is also paged just as the rest of the normal paged code, with
 * the difference that it's preloaded during boot. When the backing store
 * is configured the entire paged binary is copied in place and then also
 * the init part. Since the init part has been relocated (references to
 * addresses updated to compensate for the new load address) this has to be
 * undone for the hashes of those pages to match with the original binary.
 *
 * If CFG_CORE_ASLR=n, nothing needs to be done as the code/ro pages are
 * unchanged.
 */
static void undo_init_relocation(uint8_t *paged_store __maybe_unused)
{
#ifdef CFG_CORE_ASLR
	unsigned long *ptr = NULL;
	const uint32_t *reloc = NULL;
	const uint32_t *reloc_end = NULL;
	unsigned long offs = boot_mmu_config.load_offset;
	const struct boot_embdata *embdata = (const void *)__init_end;
	vaddr_t addr_end = (vaddr_t)__init_end - offs - TEE_RAM_START;
	vaddr_t addr_start = (vaddr_t)__init_start - offs - TEE_RAM_START;

	reloc = (const void *)((vaddr_t)embdata + embdata->reloc_offset);
	reloc_end = reloc + embdata->reloc_len / sizeof(*reloc);

	for (; reloc < reloc_end; reloc++) {
		if (*reloc < addr_start)
			continue;
		if (*reloc >= addr_end)
			break;
		ptr = (void *)(paged_store + *reloc - addr_start);
		*ptr -= offs;
	}
#endif
}

static struct fobj *ro_paged_alloc(tee_mm_entry_t *mm, void *hashes,
				   void *store)
{
	const unsigned int num_pages = tee_mm_get_bytes(mm) / SMALL_PAGE_SIZE;
#ifdef CFG_CORE_ASLR
	unsigned int reloc_offs = (vaddr_t)__pageable_start - VCORE_START_VA;
	const struct boot_embdata *embdata = (const void *)__init_end;
	const void *reloc = __init_end + embdata->reloc_offset;

	return fobj_ro_reloc_paged_alloc(num_pages, hashes, reloc_offs,
					 reloc, embdata->reloc_len, store);
#else
	return fobj_ro_paged_alloc(num_pages, hashes, store);
#endif
}

static void init_runtime(unsigned long pageable_part)
{
	size_t n;
	size_t init_size = (size_t)(__init_end - __init_start);
	size_t pageable_start = (size_t)__pageable_start;
	size_t pageable_end = (size_t)__pageable_end;
	size_t pageable_size = pageable_end - pageable_start;
	size_t tzsram_end = TZSRAM_BASE + TZSRAM_SIZE;
	size_t hash_size = (pageable_size / SMALL_PAGE_SIZE) *
			   TEE_SHA256_HASH_SIZE;
	const struct boot_embdata *embdata = (const void *)__init_end;
	const void *tmp_hashes = NULL;
	tee_mm_entry_t *mm = NULL;
	struct fobj *fobj = NULL;
	uint8_t *paged_store = NULL;
	uint8_t *hashes = NULL;

	assert(pageable_size % SMALL_PAGE_SIZE == 0);
	assert(embdata->total_len >= embdata->hashes_offset +
				     embdata->hashes_len);
	assert(hash_size == embdata->hashes_len);

	tmp_hashes = __init_end + embdata->hashes_offset;

	init_asan();

	malloc_add_pool(__heap1_start, __heap1_end - __heap1_start);
	malloc_add_pool(__heap2_start, __heap2_end - __heap2_start);

	/*
	 * This needs to be initialized early to support address lookup
	 * in MEM_AREA_TEE_RAM
	 */
	tee_pager_early_init();

	hashes = malloc(hash_size);
	IMSG_RAW("\n");
	IMSG("Pager is enabled. Hashes: %zu bytes", hash_size);
	assert(hashes);
	asan_memcpy_unchecked(hashes, tmp_hashes, hash_size);

	/*
	 * Need tee_mm_sec_ddr initialized to be able to allocate secure
	 * DDR below.
	 */
	core_mmu_init_ta_ram();

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
	/*
	 * Undo eventual relocation for the init part so the hash checks
	 * can pass.
	 */
	undo_init_relocation(paged_store);

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
			     n, (void *)page, res);
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
	fobj = ro_paged_alloc(mm, hashes, paged_store);
	assert(fobj);
	tee_pager_add_core_area(tee_mm_get_smem(mm), PAGER_AREA_TYPE_RO, fobj);
	fobj_put(fobj);

	tee_pager_add_pages(pageable_start, init_size / SMALL_PAGE_SIZE, false);
	tee_pager_add_pages(pageable_start + init_size,
			    (pageable_size - init_size) / SMALL_PAGE_SIZE,
			    true);
	if (pageable_end < tzsram_end)
		tee_pager_add_pages(pageable_end, (tzsram_end - pageable_end) /
						   SMALL_PAGE_SIZE, true);

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
	init_asan();

	/*
	 * By default whole OP-TEE uses malloc, so we need to initialize
	 * it early. But, when virtualization is enabled, malloc is used
	 * only by TEE runtime, so malloc should be initialized later, for
	 * every virtual partition separately. Core code uses nex_malloc
	 * instead.
	 */
#ifdef CFG_VIRTUALIZATION
	nex_malloc_add_pool(__nex_heap_start, __nex_heap_end -
					      __nex_heap_start);
#else
	malloc_add_pool(__heap1_start, __heap1_end - __heap1_start);
#endif

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
	assert(cpu_mmu_enabled());
	return external_dt.blob;
}

static TEE_Result release_external_dt(void)
{
	int ret = 0;

	if (!external_dt.blob)
		return TEE_SUCCESS;

	ret = fdt_pack(external_dt.blob);
	if (ret < 0) {
		EMSG("Failed to pack Device Tree at 0x%" PRIxPA ": error %d",
		     virt_to_phys(external_dt.blob), ret);
		panic();
	}

	/* External DTB no more reached, reset pointer to invalid */
	external_dt.blob = NULL;

	return TEE_SUCCESS;
}
boot_final(release_external_dt);

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
		DMSG("OP-TEE Device Tree node already exists!");
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
		DMSG("PSCI Device Tree node already exists!");
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

	if (IS_ENABLED(CFG_EXTERNAL_DTB_OVERLAY)) {
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

#ifdef CFG_CORE_DYN_SHM
static uint64_t get_dt_val_and_advance(const void *data, size_t *offs,
				       uint32_t cell_size)
{
	uint64_t rv = 0;

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

/*
 * Find all non-secure memory from DT. Memory marked inaccessible by Secure
 * World is ignored since it could not be mapped to be used as dynamic shared
 * memory.
 */
static int get_nsec_memory_helper(void *fdt, struct core_mmu_phys_mem *mem)
{
	const uint8_t *prop = NULL;
	uint64_t a = 0;
	uint64_t l = 0;
	size_t prop_offs = 0;
	size_t prop_len = 0;
	int elems_total = 0;
	int addr_size = 0;
	int len_size = 0;
	int offs = 0;
	size_t n = 0;
	int len = 0;

	addr_size = fdt_address_cells(fdt, 0);
	if (addr_size < 0)
		return 0;

	len_size = fdt_size_cells(fdt, 0);
	if (len_size < 0)
		return 0;

	while (true) {
		offs = fdt_node_offset_by_prop_value(fdt, offs, "device_type",
						     "memory",
						     sizeof("memory"));
		if (offs < 0)
			break;

		if (_fdt_get_status(fdt, offs) != (DT_STATUS_OK_NSEC |
						   DT_STATUS_OK_SEC))
			continue;

		prop = fdt_getprop(fdt, offs, "reg", &len);
		if (!prop)
			continue;

		prop_len = len;
		for (n = 0, prop_offs = 0; prop_offs < prop_len; n++) {
			a = get_dt_val_and_advance(prop, &prop_offs, addr_size);
			if (prop_offs >= prop_len) {
				n--;
				break;
			}

			l = get_dt_val_and_advance(prop, &prop_offs, len_size);
			if (mem) {
				mem->type = MEM_AREA_DDR_OVERALL;
				mem->addr = a;
				mem->size = l;
				mem++;
			}
		}

		elems_total += n;
	}

	return elems_total;
}

static struct core_mmu_phys_mem *get_nsec_memory(void *fdt, size_t *nelems)
{
	struct core_mmu_phys_mem *mem = NULL;
	int elems_total = 0;

	elems_total = get_nsec_memory_helper(fdt, NULL);
	if (elems_total <= 0)
		return NULL;

	mem = nex_calloc(elems_total, sizeof(*mem));
	if (!mem)
		panic();

	elems_total = get_nsec_memory_helper(fdt, mem);
	assert(elems_total > 0);

	*nelems = elems_total;

	return mem;
}
#endif /*CFG_CORE_DYN_SHM*/

#ifdef CFG_CORE_RESERVED_SHM
static int mark_static_shm_as_reserved(struct dt_descriptor *dt)
{
	vaddr_t shm_start;
	vaddr_t shm_end;

	core_mmu_get_mem_by_type(MEM_AREA_NSEC_SHM, &shm_start, &shm_end);
	if (shm_start != shm_end)
		return add_res_mem_dt_node(dt, "optee_shm",
					   virt_to_phys((void *)shm_start),
					   shm_end - shm_start);

	DMSG("No SHM configured");
	return -1;
}
#endif /*CFG_CORE_RESERVED_SHM*/

static void init_external_dt(unsigned long phys_dt)
{
	struct dt_descriptor *dt = &external_dt;
	void *fdt;
	int ret;

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

	if (!core_mmu_add_mapping(MEM_AREA_EXT_DT, phys_dt, CFG_DTB_MAX_SIZE))
		panic("Failed to map external DTB");

	fdt = phys_to_virt(phys_dt, MEM_AREA_EXT_DT);
	if (!fdt)
		panic();

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

static int mark_tzdram_as_reserved(struct dt_descriptor *dt)
{
	return add_res_mem_dt_node(dt, "optee_core", CFG_TZDRAM_START,
				   CFG_TZDRAM_SIZE);
}

#ifdef CFG_CORE_RESERVE_DRIVERS
static char *strtok(char *str, const char *delims)
{
	static char *pos;
	char *start = NULL;

	if (str)
		pos = str;

	if (pos) {
		while (*pos && strchr(delims, *pos))
			pos++;

		if (*pos) {
			start = pos;
			while (*pos && !strchr(delims, *pos))
				pos++;

			if (*pos)
				*pos++ = '\0';
		}
	}

	return start;
}

static int add_descriptor_node(struct dt_descriptor *dt, const char *driver)
{
	unsigned int i = 0;
	unsigned int j = 0;
	char root_name[50] = { '\0' };
	char buffer[200] = { '\0' };
	char *item[10] = { NULL };
	char *root = NULL;
	int offs = 0;

	/* strok will modify the buffer */
	strncpy(buffer, driver, sizeof(buffer));

	root = strtok(buffer, "/");
	if (!root)
		return -1;

	for (i = 0; i < ARRAY_SIZE(item); i++) {
		item[i] = strtok(NULL, "/");
		if (!item[i])
			break;
	}

	if (i >= ARRAY_SIZE(item))
		return -1;

	if (fdt_path_offset(dt->blob, driver) >= 0)
		return 0;

	/* add the root node name */
	snprintf(root_name, sizeof(root_name), "/%s", root);
	offs = fdt_path_offset(dt->blob, root_name);
	if (offs < 0) {
		offs = add_dt_path_subnode(dt, "/", root);
		if (offs < 0)
			return -1;
	}

	for (j = 0; j < i; j++) {
		offs = fdt_add_subnode(dt->blob, offs, item[j]);
		if (offs < 0)
			return -1;
	}

	return offs;
}

static int reserve_drivers(struct dt_descriptor *dt)
{
	static const char * const driver[] = {
		CFG_CORE_RESERVE_DRIVERS,
		NULL,
	};
	unsigned int i = 0;
	int offs = 0;

	while (driver[i]) {
		offs = add_descriptor_node(dt, driver[i]);
		if (offs < 0)
			return -1;
		i++;

		if (!offs)
			continue;

		if (fdt_setprop_string(dt->blob, offs, "status", "disabled"))
			return -1;

		if (fdt_setprop_string(dt->blob, offs, "secure-status", "okay"))
			return -1;
	}

	return 0;
}
#endif

static void update_external_dt(void)
{
	struct dt_descriptor *dt = &external_dt;

	if (!dt->blob)
		return;

	if (add_optee_dt_node(dt))
		panic("Failed to add OP-TEE Device Tree node");

	if (config_psci(dt))
		panic("Failed to config PSCI");

#ifdef CFG_CORE_RESERVE_DRIVERS
	if (reserve_drivers(dt))
		panic("Failed to reserve drivers for OP-TEE exclusive access");
#endif

#ifdef CFG_CORE_RESERVED_SHM
	if (mark_static_shm_as_reserved(dt))
		panic("Failed to config non-secure memory");
#endif

	if (mark_tzdram_as_reserved(dt))
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

#ifdef CFG_CORE_DYN_SHM
static struct core_mmu_phys_mem *get_nsec_memory(void *fdt __unused,
						 size_t *nelems __unused)
{
	return NULL;
}
#endif /*CFG_CORE_DYN_SHM*/
#endif /*!CFG_DT*/

#ifdef CFG_CORE_DYN_SHM
static void discover_nsec_memory(void)
{
	struct core_mmu_phys_mem *mem;
	const struct core_mmu_phys_mem *mem_begin = NULL;
	const struct core_mmu_phys_mem *mem_end = NULL;
	size_t nelems;
	void *fdt = get_external_dt();

	if (fdt) {
		mem = get_nsec_memory(fdt, &nelems);
		if (mem) {
			core_mmu_set_discovered_nsec_ddr(mem, nelems);
			return;
		}

		DMSG("No non-secure memory found in FDT");
	}

	mem_begin = phys_ddr_overall_begin;
	mem_end = phys_ddr_overall_end;
	nelems = mem_end - mem_begin;
	if (nelems) {
		/*
		 * Platform cannot use both register_ddr() and the now
		 * deprecated register_dynamic_shm().
		 */
		assert(phys_ddr_overall_compat_begin ==
		       phys_ddr_overall_compat_end);
	} else {
		mem_begin = phys_ddr_overall_compat_begin;
		mem_end = phys_ddr_overall_compat_end;
		nelems = mem_end - mem_begin;
		if (!nelems)
			return;
		DMSG("Warning register_dynamic_shm() is deprecated, please use register_ddr() instead");
	}

	mem = nex_calloc(nelems, sizeof(*mem));
	if (!mem)
		panic();

	memcpy(mem, phys_ddr_overall_begin, sizeof(*mem) * nelems);
	core_mmu_set_discovered_nsec_ddr(mem, nelems);
}
#else /*CFG_CORE_DYN_SHM*/
static void discover_nsec_memory(void)
{
}
#endif /*!CFG_CORE_DYN_SHM*/

void init_tee_runtime(void)
{
#ifdef CFG_VIRTUALIZATION
	/* We need to initialize pool for every virtual guest partition */
	malloc_add_pool(__heap1_start, __heap1_end - __heap1_start);
#endif

#ifndef CFG_WITH_PAGER
	/* Pager initializes TA RAM early */
	core_mmu_init_ta_ram();
#endif
	call_initcalls();
}

static void init_primary(unsigned long pageable_part, unsigned long nsec_entry)
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
	/*
	 * Pager: init_runtime() calls thread_kernel_enable_vfp() so we must
	 * set a current thread right now to avoid a chicken-and-egg problem
	 * (thread_init_boot_thread() sets the current thread but needs
	 * things set by init_runtime()).
	 */
	thread_get_core_local()->curr_thread = 0;
	init_runtime(pageable_part);

	if (IS_ENABLED(CFG_VIRTUALIZATION)) {
		/*
		 * Virtualization: We can't initialize threads right now because
		 * threads belong to "tee" part and will be initialized
		 * separately per each new virtual guest. So, we'll clear
		 * "curr_thread" and call it done.
		 */
		thread_get_core_local()->curr_thread = -1;
	} else {
		thread_init_boot_thread();
	}
	thread_init_primary();
	thread_init_per_cpu();
	init_sec_mon(nsec_entry);
}

/*
 * Note: this function is weak just to make it possible to exclude it from
 * the unpaged area.
 */
void __weak paged_init_primary(unsigned long fdt)
{
	init_external_dt(fdt);
	tpm_map_log_area(get_external_dt());
	discover_nsec_memory();
	update_external_dt();
	configure_console_from_dt();

	IMSG("OP-TEE version: %s", core_v_str);
	IMSG("Primary CPU initializing");
#ifdef CFG_CORE_ASLR
	DMSG("Executing at offset %#lx with virtual load address %#"PRIxVA,
	     (unsigned long)boot_mmu_config.load_offset, VCORE_START_VA);
#endif

	main_init_gic();
	init_vfp_nsec();
#ifndef CFG_VIRTUALIZATION
	init_tee_runtime();
#endif
#ifdef CFG_VIRTUALIZATION
	IMSG("Initializing virtualization support");
	core_mmu_init_virtualization();
#endif
	call_finalcalls();
	IMSG("Primary CPU switching to normal world boot");
}

static void init_secondary_helper(unsigned long nsec_entry)
{
	IMSG("Secondary CPU %zu initializing", get_core_pos());

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

	IMSG("Secondary CPU %zu switching to normal world boot", get_core_pos());
}

/*
 * Note: this function is weak just to make it possible to exclude it from
 * the unpaged area so that it lies in the init area.
 */
void __weak boot_init_primary(unsigned long pageable_part,
			      unsigned long nsec_entry __maybe_unused,
			      unsigned long fdt)
{
	unsigned long e = PADDR_INVALID;

#if !defined(CFG_WITH_ARM_TRUSTED_FW)
	e = nsec_entry;
#endif

	init_primary(pageable_part, e);
	paged_init_primary(fdt);
}

#if defined(CFG_WITH_ARM_TRUSTED_FW)
unsigned long boot_cpu_on_handler(unsigned long a0 __maybe_unused,
				  unsigned long a1 __unused)
{
	init_secondary_helper(PADDR_INVALID);
	return 0;
}
#else
void boot_init_secondary(unsigned long nsec_entry)
{
	init_secondary_helper(nsec_entry);
}
#endif

#if defined(CFG_BOOT_SECONDARY_REQUEST)
void boot_set_core_ns_entry(size_t core_idx, uintptr_t entry,
			    uintptr_t context_id)
{
	ns_entry_contexts[core_idx].entry_point = entry;
	ns_entry_contexts[core_idx].context_id = context_id;
	dsb_ishst();
}

int boot_core_release(size_t core_idx, paddr_t entry)
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
struct ns_entry_context *boot_core_hpen(void)
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

#if defined(CFG_CORE_ASLR)
#if defined(CFG_DT)
unsigned long __weak get_aslr_seed(void *fdt)
{
	int rc = fdt_check_header(fdt);
	const uint64_t *seed = NULL;
	int offs = 0;
	int len = 0;

	if (rc) {
		DMSG("Bad fdt: %d", rc);
		return 0;
	}

	offs =  fdt_path_offset(fdt, "/secure-chosen");
	if (offs < 0) {
		DMSG("Cannot find /secure-chosen");
		return 0;
	}
	seed = fdt_getprop(fdt, offs, "kaslr-seed", &len);
	if (!seed || len != sizeof(*seed)) {
		DMSG("Cannot find valid kaslr-seed");
		return 0;
	}

	return fdt64_to_cpu(*seed);
}
#else /*!CFG_DT*/
unsigned long __weak get_aslr_seed(void *fdt __unused)
{
	DMSG("Warning: no ASLR seed");
	return 0;
}
#endif /*!CFG_DT*/
#endif /*CFG_CORE_ASLR*/
