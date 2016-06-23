/*
 * Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <arm.h>
#include <assert.h>
#include <compiler.h>
#include <inttypes.h>
#include <kernel/generic_boot.h>
#include <kernel/thread.h>
#include <kernel/panic.h>
#include <kernel/misc.h>
#include <malloc.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <mm/tee_mm.h>
#include <mm/tee_mmu.h>
#include <mm/tee_pager.h>
#include <sm/tee_mon.h>
#include <trace.h>
#include <tee/tee_cryp_provider.h>
#include <utee_defines.h>
#include <util.h>
#include <stdio.h>

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

#ifdef CFG_BOOT_SYNC_CPU
/*
 * Array used when booting, to synchronize cpu.
 * When 0, the cpu has not started.
 * When 1, it has started
 */
uint32_t sem_cpu_sync[CFG_TEE_CORE_NB_CORE] __data;
#endif

/* May be overridden in plat-$(PLATFORM)/main.c */
__weak void main_init_gic(void)
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

#ifdef CFG_WITH_PAGER

static size_t get_block_size(void)
{
	struct core_mmu_table_info tbl_info;
	unsigned l;

	if (!core_mmu_find_table(CFG_TEE_RAM_START, UINT_MAX, &tbl_info))
		panic();
	l = tbl_info.level - 1;
	if (!core_mmu_find_table(CFG_TEE_RAM_START, l, &tbl_info))
		panic();
	return 1 << tbl_info.shift;
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
	size_t block_size;

	TEE_ASSERT(pageable_size % SMALL_PAGE_SIZE == 0);
	TEE_ASSERT(hash_size == (size_t)__tmp_hashes_size);

	/*
	 * Zero BSS area. Note that globals that would normally would go
	 * into BSS which are used before this has to be put into .nozi.*
	 * to avoid getting overwritten.
	 */
	memset(__bss_start, 0, __bss_end - __bss_start);

	core_mmu_linear_map_end = (vaddr_t)__heap2_end;
	/*
	 * This needs to be initialized early to support address lookup
	 * in MEM_AREA_TEE_RAM
	 */
	if (!core_mmu_find_table(CFG_TEE_RAM_START, UINT_MAX,
				 &tee_pager_tbl_info))
		panic();
	if (tee_pager_tbl_info.shift != SMALL_PAGE_SHIFT) {
		EMSG("Unsupported page size in translation table %u",
		     BIT(tee_pager_tbl_info.shift));
		panic();
	}

	thread_init_boot_thread();

	malloc_add_pool(__heap1_start, __heap1_end - __heap1_start);
	malloc_add_pool(__heap2_start, __heap2_end - __heap2_start);

	hashes = malloc(hash_size);
	IMSG("Pager is enabled. Hashes: %zu bytes", hash_size);
	TEE_ASSERT(hashes);
	memcpy(hashes, __tmp_hashes_start, hash_size);

	/*
	 * Need tee_mm_sec_ddr initialized to be able to allocate secure
	 * DDR below.
	 */
	teecore_init_ta_ram();

	mm = tee_mm_alloc(&tee_mm_sec_ddr, pageable_size);
	TEE_ASSERT(mm);
	paged_store = phys_to_virt(tee_mm_get_smem(mm), MEM_AREA_TA_RAM);
	/* Copy init part into pageable area */
	memcpy(paged_store, __init_start, init_size);
	/* Copy pageable part after init part into pageable area */
	memcpy(paged_store + init_size,
	       phys_to_virt(pageable_part,
			    core_mmu_get_type_by_pa(pageable_part)),
		__pageable_part_end - __pageable_part_start);

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
	 * Copy what's not initialized in the last init page. Needed
	 * because we're not going fault in the init pages again. We can't
	 * fault in pages until we've switched to the new vector by calling
	 * thread_init_handlers() below.
	 */
	if (init_size % SMALL_PAGE_SIZE) {
		uint8_t *p;

		memcpy(__init_start + init_size, paged_store + init_size,
			SMALL_PAGE_SIZE - (init_size % SMALL_PAGE_SIZE));

		p = (uint8_t *)(((vaddr_t)__init_start + init_size) &
				~SMALL_PAGE_MASK);

		cache_maintenance_l1(DCACHE_AREA_CLEAN, p, SMALL_PAGE_SIZE);
		cache_maintenance_l1(ICACHE_AREA_INVALIDATE, p,
				     SMALL_PAGE_SIZE);
	}

	/*
	 * Initialize the virtual memory pool used for main_mmu_l2_ttb which
	 * is supplied to tee_pager_init() below.
	 */
	block_size = get_block_size();
	if (!tee_mm_init(&tee_mm_vcore,
			ROUNDDOWN(CFG_TEE_RAM_START, block_size),
			ROUNDUP(CFG_TEE_RAM_START + CFG_TEE_RAM_VA_SIZE,
				block_size),
			SMALL_PAGE_SHIFT, 0))
		panic();

	/*
	 * Assign alias area for pager end of the small page block the rest
	 * of the binary is loaded into. We're taking more than needed, but
	 * we're guaranteed to not need more than the physical amount of
	 * TZSRAM.
	 */
	mm = tee_mm_alloc2(&tee_mm_vcore,
		(vaddr_t)tee_mm_vcore.hi - TZSRAM_SIZE, TZSRAM_SIZE);
	TEE_ASSERT(mm);
	tee_pager_init(mm);

	/*
	 * Claim virtual memory which isn't paged, note that there migth be
	 * a gap between tee_mm_vcore.lo and TEE_RAM_START which is also
	 * claimed to avoid later allocations to get that memory.
	 */
	mm = tee_mm_alloc2(&tee_mm_vcore, tee_mm_vcore.lo,
			(vaddr_t)(__text_init_start - tee_mm_vcore.lo));
	TEE_ASSERT(mm);

	/*
	 * Allocate virtual memory for the pageable area and let the pager
	 * take charge of all the pages already assigned to that memory.
	 */
	mm = tee_mm_alloc2(&tee_mm_vcore, (vaddr_t)__pageable_start,
			   pageable_size);
	TEE_ASSERT(mm);
	if (!tee_pager_add_core_area(tee_mm_get_smem(mm), tee_mm_get_bytes(mm),
				     TEE_MATTR_PRX, paged_store, hashes))
		panic();
	tee_pager_add_pages((vaddr_t)__pageable_start,
		ROUNDUP(init_size, SMALL_PAGE_SIZE) / SMALL_PAGE_SIZE, false);
	tee_pager_add_pages((vaddr_t)__pageable_start +
				ROUNDUP(init_size, SMALL_PAGE_SIZE),
			(pageable_size - ROUNDUP(init_size, SMALL_PAGE_SIZE)) /
				SMALL_PAGE_SIZE, true);

}
#else
static void init_runtime(unsigned long pageable_part __unused)
{
	/*
	 * Zero BSS area. Note that globals that would normally would go
	 * into BSS which are used before this has to be put into .nozi.*
	 * to avoid getting overwritten.
	 */
	memset(__bss_start, 0, __bss_end - __bss_start);

	thread_init_boot_thread();

	malloc_add_pool(__heap1_start, __heap1_end - __heap1_start);

	/*
	 * Initialized at this stage in the pager version of this function
	 * above
	 */
	teecore_init_ta_ram();
}
#endif

#ifdef CFG_DT
static int add_optee_dt_node(void *fdt)
{
	int offs;
	int ret;

	if (fdt_path_offset(fdt, "/firmware/optee") >= 0) {
		IMSG("OP-TEE Device Tree node already exists!\n");
		return 0;
	}

	offs = fdt_path_offset(fdt, "/firmware");
	if (offs < 0) {
		offs = fdt_path_offset(fdt, "/");
		if (offs < 0)
			return -1;
		offs = fdt_add_subnode(fdt, offs, "firmware");
		if (offs < 0)
			return -1;
	}

	offs = fdt_add_subnode(fdt, offs, "optee");
	if (offs < 0)
		return -1;

	ret = fdt_setprop_string(fdt, offs, "compatible", "linaro,optee-tz");
	if (ret < 0)
		return -1;
	ret = fdt_setprop_string(fdt, offs, "method", "smc");
	if (ret < 0)
		return -1;
	return 0;
}

static int get_dt_cell_size(void *fdt, int offs, const char *cell_name,
			    uint32_t *cell_size)
{
	int len;
	const uint32_t *cell = fdt_getprop(fdt, offs, cell_name, &len);

	if (len != sizeof(*cell))
		return -1;
	*cell_size = fdt32_to_cpu(*cell);
	if (*cell_size != 1 && *cell_size != 2)
		return -1;
	return 0;
}

static void set_dt_val(void *data, uint32_t cell_size, uint64_t val)
{
	if (cell_size == 1) {
		uint32_t v = cpu_to_fdt32((uint32_t)val);

		memcpy(data, &v, sizeof(v));
	} else {
		uint64_t v = cpu_to_fdt64(val);

		memcpy(data, &v, sizeof(v));
	}
}

static int add_optee_res_mem_dt_node(void *fdt)
{
	int offs;
	int ret;
	uint32_t addr_size = 2;
	uint32_t len_size = 2;
	vaddr_t shm_va_start;
	vaddr_t shm_va_end;
	paddr_t shm_pa;
	char subnode_name[80];

	offs = fdt_path_offset(fdt, "/reserved-memory");
	if (offs >= 0) {
		ret = get_dt_cell_size(fdt, offs, "#address-cells", &addr_size);
		if (ret < 0)
			return -1;
		ret = get_dt_cell_size(fdt, offs, "#size-cells", &len_size);
		if (ret < 0)
			return -1;
	} else {
		offs = fdt_path_offset(fdt, "/");
		if (offs < 0)
			return -1;
		offs = fdt_add_subnode(fdt, offs, "reserved-memory");
		if (offs < 0)
			return -1;
		ret = fdt_setprop_cell(fdt, offs, "#address-cells", addr_size);
		if (ret < 0)
			return -1;
		ret = fdt_setprop_cell(fdt, offs, "#size-cells", len_size);
		if (ret < 0)
			return -1;
		ret = fdt_setprop(fdt, offs, "ranges", NULL, 0);
		if (ret < 0)
			return -1;
	}

	core_mmu_get_mem_by_type(MEM_AREA_NSEC_SHM, &shm_va_start, &shm_va_end);
	shm_pa = virt_to_phys((void *)shm_va_start);
	snprintf(subnode_name, sizeof(subnode_name),
		 "optee@0x%" PRIxPA, shm_pa);
	offs = fdt_add_subnode(fdt, offs, subnode_name);
	if (offs >= 0) {
		uint32_t data[addr_size + len_size] ;

		set_dt_val(data, addr_size, shm_pa);
		set_dt_val(data + addr_size, len_size,
			   shm_va_end - shm_va_start);
		ret = fdt_setprop(fdt, offs, "reg", data, sizeof(data));
		if (ret < 0)
			return -1;
	} else {
		return -1;
	}
	return 0;
}

static void init_fdt(unsigned long phys_fdt)
{
	void *fdt;
	int ret;

	if (!phys_fdt) {
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

	if (!core_mmu_add_mapping(MEM_AREA_IO_NSEC, phys_fdt, CFG_DTB_MAX_SIZE))
		panic();
	fdt = phys_to_virt(phys_fdt, MEM_AREA_IO_NSEC);
	if (!fdt)
		panic();

	ret = fdt_open_into(fdt, fdt, CFG_DTB_MAX_SIZE);
	if (ret < 0) {
		EMSG("Invalid Device Tree at 0x%" PRIxPA ": error %d",
		     phys_fdt, ret);
		panic();
	}

	if (add_optee_dt_node(fdt)) {
		EMSG("Failed to add OP-TEE Device Tree node");
		panic();
	}
	if (add_optee_res_mem_dt_node(fdt)) {
		EMSG("Failed to add OP-TEE reserved memory Device Tree node");
		panic();
	}

	ret = fdt_pack(fdt);
	if (ret < 0) {
		EMSG("Failed to pack Device Tree at 0x%" PRIxPA ": error %d",
		     phys_fdt, ret);
		panic();
	}
}
#else
static void init_fdt(unsigned long phys_fdt __unused)
{
}
#endif /*!CFG_DT*/

static void init_primary_helper(unsigned long pageable_part,
				unsigned long nsec_entry, unsigned long fdt)
{
	/*
	 * Mask asynchronous exceptions before switch to the thread vector
	 * as the thread handler requires those to be masked while
	 * executing with the temporary stack. The thread subsystem also
	 * asserts that IRQ is blocked when using most if its functions.
	 */
	thread_set_exceptions(THREAD_EXCP_ALL);
	init_vfp_sec();

	init_runtime(pageable_part);

	IMSG("Initializing (%s)\n", core_v_str);

	thread_init_primary(generic_boot_get_handlers());
	thread_init_per_cpu();
	init_sec_mon(nsec_entry);
	init_fdt(fdt);
	main_init_gic();
	init_vfp_nsec();

	if (init_teecore() != TEE_SUCCESS)
		panic();
	DMSG("Primary CPU switching to normal world boot\n");
}

static void init_secondary_helper(unsigned long nsec_entry)
{
	/*
	 * Mask asynchronous exceptions before switch to the thread vector
	 * as the thread handler requires those to be masked while
	 * executing with the temporary stack. The thread subsystem also
	 * asserts that IRQ is blocked when using most if its functions.
	 */
	thread_set_exceptions(THREAD_EXCP_ALL);

	thread_init_per_cpu();
	init_sec_mon(nsec_entry);
	init_vfp_sec();
	init_vfp_nsec();

	DMSG("Secondary CPU Switching to normal world boot\n");
}

#if defined(CFG_WITH_ARM_TRUSTED_FW)
uint32_t *generic_boot_init_primary(unsigned long pageable_part,
				    unsigned long u __unused,
				    unsigned long fdt)
{
	init_primary_helper(pageable_part, PADDR_INVALID, fdt);
	return thread_vector_table;
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
