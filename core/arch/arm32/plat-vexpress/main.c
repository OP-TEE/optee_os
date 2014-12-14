/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
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

#include <platform_config.h>
#include <pm_debug.h>

#include <stdint.h>
#include <string.h>

#include <drivers/gic.h>
#include <drivers/uart.h>
#include <sm/sm.h>
#include <sm/sm_defs.h>
#include <sm/tee_mon.h>

#include <util.h>
#include <kernel/arch_debug.h>

#include <arm32.h>
#include <kernel/thread.h>
#include <kernel/panic.h>
#include <trace.h>
#include <kernel/misc.h>
#include <kernel/tee_time.h>
#include <mm/tee_pager.h>
#include <mm/core_mmu.h>
#include <mm/tee_mmu_defs.h>
#include <mm/tee_mmu.h>
#include <mm/tee_mm.h>
#include <utee_defines.h>
#include <tee/tee_cryp_provider.h>
#include <tee/entry.h>
#include <tee/arch_svc.h>
#include <console.h>
#include <malloc.h>
#include "plat_tee_func.h"

#include <assert.h>

#define PADDR_INVALID		0xffffffff

#ifdef WITH_STACK_CANARIES
#define STACK_CANARY_SIZE	(4 * sizeof(uint32_t))
#define START_CANARY_VALUE	0xdededede
#define END_CANARY_VALUE	0xabababab
#define GET_START_CANARY(name, stack_num) name[stack_num][0]
#define GET_END_CANARY(name, stack_num) \
	name[stack_num][sizeof(name[stack_num]) / sizeof(uint32_t) - 1]
#else
#define STACK_CANARY_SIZE	0
#endif

#define DECLARE_STACK(name, num_stacks, stack_size) \
	static uint32_t name[num_stacks][ \
		ROUNDUP(stack_size + STACK_CANARY_SIZE, STACK_ALIGNMENT) / \
		sizeof(uint32_t)] \
		__attribute__((section(".nozi.stack"), \
			       aligned(STACK_ALIGNMENT)))

#define GET_STACK(stack) \
	((vaddr_t)(stack) + sizeof(stack) - STACK_CANARY_SIZE / 2)


DECLARE_STACK(stack_tmp,	CFG_TEE_CORE_NB_CORE,	STACK_TMP_SIZE);
DECLARE_STACK(stack_abt,	CFG_TEE_CORE_NB_CORE,	STACK_ABT_SIZE);
DECLARE_STACK(stack_sm,		CFG_TEE_CORE_NB_CORE,	SM_STACK_SIZE);
#ifndef CFG_WITH_PAGER
DECLARE_STACK(stack_thread,	NUM_THREADS,		STACK_THREAD_SIZE);
#endif

const vaddr_t stack_tmp_top[CFG_TEE_CORE_NB_CORE] = {
	GET_STACK(stack_tmp[0]),
#if CFG_TEE_CORE_NB_CORE > 1
	GET_STACK(stack_tmp[1]),
#endif
#if CFG_TEE_CORE_NB_CORE > 2
	GET_STACK(stack_tmp[2]),
#endif
#if CFG_TEE_CORE_NB_CORE > 3
	GET_STACK(stack_tmp[3]),
#endif
#if CFG_TEE_CORE_NB_CORE > 4
	GET_STACK(stack_tmp[4]),
#endif
#if CFG_TEE_CORE_NB_CORE > 5
	GET_STACK(stack_tmp[5]),
#endif
#if CFG_TEE_CORE_NB_CORE > 6
	GET_STACK(stack_tmp[6]),
#endif
#if CFG_TEE_CORE_NB_CORE > 7
	GET_STACK(stack_tmp[7]),
#endif
#if CFG_TEE_CORE_NB_CORE > 8
#error "Top of tmp stacks aren't defined for more than 8 CPUS"
#endif
};

/* Main MMU L1 table for teecore */
static uint32_t main_mmu_l1_ttb[TEE_MMU_L1_NUM_ENTRIES]
	__attribute__((section(".nozi.mmu.l1"),
		       aligned(TEE_MMU_L1_ALIGNMENT)));
static uint32_t main_mmu_l2_ttb[TEE_MMU_L2_NUM_ENTRIES]
	__attribute__((section(".nozi.mmu.l2"),
		       aligned(TEE_MMU_L2_ALIGNMENT)));

/* MMU L1 table for TAs, one for each Core */
static uint32_t main_mmu_ul1_ttb[NUM_THREADS][TEE_MMU_UL1_NUM_ENTRIES]
        __attribute__((section(".nozi.mmu.ul1"),
		      aligned(TEE_MMU_UL1_ALIGNMENT)));

extern uint8_t __text_init_start[];
extern uint8_t __data_start[];
extern uint8_t __data_end[];
extern uint8_t __bss_start[];
extern uint8_t __bss_end[];
extern uint8_t __init_start[];
extern uint8_t __init_size[];
extern uint8_t __heap1_start[];
extern uint8_t __heap1_end[];
extern uint8_t __heap2_start[];
extern uint8_t __heap2_end[];
extern uint8_t __pagable_part_start[];
extern uint8_t __pagable_part_end[];
extern uint8_t __pagable_start[];
extern uint8_t __pagable_end[];

static void main_fiq(void);
#if defined(WITH_ARM_TRUSTED_FW)
/* Implemented in assembly, referenced in this file only */
uint32_t cpu_on_handler(uint32_t a0, uint32_t a1);

static uint32_t main_cpu_off_handler(uint32_t a0, uint32_t a1);
static uint32_t main_cpu_suspend_handler(uint32_t a0, uint32_t a1);
static uint32_t main_cpu_resume_handler(uint32_t a0, uint32_t a1);
static uint32_t main_system_off_handler(uint32_t a0, uint32_t a1);
static uint32_t main_system_reset_handler(uint32_t a0, uint32_t a1);
#elif defined(WITH_SEC_MON)
static uint32_t main_default_pm_handler(uint32_t a0, uint32_t a1);
#else
#error Platform must use either ARM_TRUSTED_FW or SEC_MON
#endif

static void init_canaries(void)
{
	size_t n;
#define INIT_CANARY(name)						\
	for (n = 0; n < ARRAY_SIZE(name); n++) {			\
		uint32_t *start_canary = &GET_START_CANARY(name, n);	\
		uint32_t *end_canary = &GET_END_CANARY(name, n);	\
									\
		*start_canary = START_CANARY_VALUE;			\
		*end_canary = END_CANARY_VALUE;				\
		DMSG("#Stack canaries for %s[%zu] with top at %p\n",	\
			#name, n, (void *)(end_canary - 1));		\
		DMSG("watch *%p\n", (void *)end_canary);	\
	}

	INIT_CANARY(stack_tmp);
	INIT_CANARY(stack_abt);
	INIT_CANARY(stack_sm);
#ifndef CFG_WITH_PAGER
	INIT_CANARY(stack_thread);
#endif
}

void check_canaries(void)
{
#ifdef WITH_STACK_CANARIES
	size_t n;

#define ASSERT_STACK_CANARIES(name)					\
	for (n = 0; n < ARRAY_SIZE(name); n++) {			\
		assert(GET_START_CANARY(name, n) == START_CANARY_VALUE);\
		assert(GET_END_CANARY(name, n) == END_CANARY_VALUE);	\
	} while (0)

	ASSERT_STACK_CANARIES(stack_tmp);
	ASSERT_STACK_CANARIES(stack_abt);
	ASSERT_STACK_CANARIES(stack_sm);
#ifndef CFG_WITH_PAGER
	ASSERT_STACK_CANARIES(stack_thread);
#endif
#endif /*WITH_STACK_CANARIES*/
}

static const struct thread_handlers handlers = {
	.std_smc = plat_tee_entry,
	.fast_smc = plat_tee_entry,
	.fiq = main_fiq,
	.svc = tee_svc_handler,
	.abort = tee_pager_abort_handler,
#if defined(WITH_ARM_TRUSTED_FW)
	.cpu_on = cpu_on_handler,
	.cpu_off = main_cpu_off_handler,
	.cpu_suspend = main_cpu_suspend_handler,
	.cpu_resume = main_cpu_resume_handler,
	.system_off = main_system_off_handler,
	.system_reset = main_system_reset_handler,
#elif defined(WITH_SEC_MON)
	.cpu_on = main_default_pm_handler,
	.cpu_off = main_default_pm_handler,
	.cpu_suspend = main_default_pm_handler,
	.cpu_resume = main_default_pm_handler,
	.system_off = main_default_pm_handler,
	.system_reset = main_default_pm_handler,
#endif
};

#if defined(WITH_ARM_TRUSTED_FW)
static void main_init_sec_mon(size_t pos, uint32_t nsec_entry)
{
	(void)&pos;
	(void)&nsec_entry;
	assert(nsec_entry == PADDR_INVALID);
	/* Do nothing as we don't have a secure monitor */
}
#elif defined(WITH_SEC_MON)
static void main_init_sec_mon(size_t pos, uint32_t nsec_entry)
{
	struct sm_nsec_ctx *nsec_ctx;

	assert(nsec_entry != PADDR_INVALID);

	/* Initialize secure monitor */
	sm_init(GET_STACK(stack_sm[pos]));
	nsec_ctx = sm_get_nsec_ctx();
	nsec_ctx->mon_lr = nsec_entry;
	nsec_ctx->mon_spsr = CPSR_MODE_SVC | CPSR_I;
	sm_set_entry_vector(thread_vector_table);

}
#endif

#if defined(WITH_ARM_TRUSTED_FW)
static void main_init_nsacr(void)
{
}
#else
static void main_init_nsacr(void)
{
	/* Normal world can use CP10 and CP11 (SIMD/VFP) */
	write_nsacr(read_nsacr() | NSACR_CP10 | NSACR_CP11);
}
#endif

#ifdef CFG_WITH_VFP
static void main_init_cpacr(void)
{
	uint32_t cpacr = read_cpacr();

	/* Enabled usage of CP10 and CP11 (SIMD/VFP) */
	cpacr &= ~CPACR_CP(10, CPACR_CP_ACCESS_FULL);
	cpacr |= CPACR_CP(10, CPACR_CP_ACCESS_PL1_ONLY);
	cpacr &= ~CPACR_CP(11, CPACR_CP_ACCESS_FULL);
	cpacr |= CPACR_CP(11, CPACR_CP_ACCESS_PL1_ONLY);
	write_cpacr(cpacr);
}
#else
static void main_init_cpacr(void)
{
	/* We're not using VFP/SIMD instructions, leave it disabled */
}
#endif

#if PLATFORM_FLAVOR_IS(fvp) || PLATFORM_FLAVOR_IS(juno)
static void main_init_gic(void)
{
	/*
	 * On ARMv8, GIC configuration is initialized in ARM-TF,
	 */
	gic_init_base_addr(GIC_BASE + GICC_OFFSET, GIC_BASE + GICD_OFFSET);
	gic_it_add(IT_CONSOLE_UART);
	/* Route FIQ to primary CPU */
	gic_it_set_cpu_mask(IT_CONSOLE_UART, gic_it_get_target(0));
	gic_it_set_prio(IT_CONSOLE_UART, 0x1);
	gic_it_enable(IT_CONSOLE_UART);

}
#elif PLATFORM_FLAVOR_IS(qemu)
static void main_init_gic(void)
{
	/* Initialize GIC */
	gic_init(GIC_BASE + GICC_OFFSET, GIC_BASE + GICD_OFFSET);
	gic_it_add(IT_CONSOLE_UART);
	gic_it_set_cpu_mask(IT_CONSOLE_UART, 0x1);
	gic_it_set_prio(IT_CONSOLE_UART, 0xff);
	gic_it_enable(IT_CONSOLE_UART);
}
#elif PLATFORM_FLAVOR_IS(qemu_virt)
static void main_init_gic(void)
{
	/* Initialize GIC */
	gic_init(GIC_BASE + GICC_OFFSET, GIC_BASE + GICD_OFFSET);
}
#endif

#ifdef CFG_WITH_PAGER
static void main_init_runtime(uint32_t pagable_part)
{
	size_t n;
	size_t init_size = (size_t)__init_size;
	size_t pagable_size = __pagable_end - __pagable_start;
	size_t hash_size = (pagable_size / SMALL_PAGE_SIZE) *
			   TEE_SHA256_HASH_SIZE;
	tee_mm_entry_t *mm;
	uint8_t *paged_store;
	uint8_t *hashes;
	uint8_t *tmp_hashes = __init_start + init_size;


	TEE_ASSERT(pagable_size % SMALL_PAGE_SIZE == 0);


	/* Copy it right after the init area. */
	memcpy(tmp_hashes, __data_end + init_size, hash_size);

	/*
	 * Zero BSS area. Note that globals that would normally would go
	 * into BSS which are used before this has to be put into .nozi.*
	 * to avoid getting overwritten.
	 */
	memset(__bss_start, 0, __bss_end - __bss_start);

	malloc_init(__heap1_start, __heap1_end - __heap1_start);
	malloc_add_pool(__heap2_start, __heap2_end - __heap2_start);

	hashes = malloc(hash_size);
	EMSG("hash_size %d", hash_size);
	TEE_ASSERT(hashes);
	memcpy(hashes, tmp_hashes, hash_size);

	/*
	 * Need tee_mm_sec_ddr initialized to be able to allocate secure
	 * DDR below.
	 */
	teecore_init_ta_ram();

	mm = tee_mm_alloc(&tee_mm_sec_ddr, pagable_size);
	TEE_ASSERT(mm);
	paged_store = (uint8_t *)tee_mm_get_smem(mm);
	/* Copy init part into pagable area */
	memcpy(paged_store, __init_start, init_size);
	/* Copy pagable part after init part into pagable area */
	memcpy(paged_store + init_size, (void *)pagable_part,
		__pagable_part_end - __pagable_part_start);

	/* Check that hashes of what's in pagable area is OK */
	DMSG("Checking hashes of pagable area");
	for (n = 0; (n * SMALL_PAGE_SIZE) < pagable_size; n++) {
		const uint8_t *hash = hashes + n * TEE_SHA256_HASH_SIZE;
		const uint8_t *page = paged_store + n * SMALL_PAGE_SIZE;
		TEE_Result res;

		DMSG("hash pg_idx %zu hash %p page %p", n, hash, page);
		res = hash_sha256_check(hash, page, SMALL_PAGE_SIZE);
		if (res != TEE_SUCCESS)
			EMSG("Hash failed for page %zu at %p: res 0x%x",
				n, page, res);
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
	 * Inialize the virtual memory pool used for main_mmu_l2_ttb which
	 * is supplied to tee_pager_init() below.
	 */
	if (!tee_mm_init(&tee_mm_vcore,
			ROUNDDOWN(CFG_TEE_RAM_START, SECTION_SIZE),
			ROUNDDOWN(CFG_TEE_RAM_START + CFG_TEE_RAM_VA_SIZE,
				  SECTION_SIZE),
			SMALL_PAGE_SHIFT, 0))
		panic();

	tee_pager_init(main_mmu_l2_ttb);

	/*
	 * Claim virtual memory which isn't paged, note that there migth be
	 * a gap between tee_mm_vcore.lo and TEE_RAM_START which is also
	 * claimed to avoid later allocations to get that memory.
	 */
	mm = tee_mm_alloc2(&tee_mm_vcore, tee_mm_vcore.lo,
			(vaddr_t)(__text_init_start - tee_mm_vcore.lo));
	TEE_ASSERT(mm);

	/*
	 * Allocate virtual memory for the pagable area and let the pager
	 * take charge of all the pages already assigned to that memory.
	 */
	mm = tee_mm_alloc2(&tee_mm_vcore, (vaddr_t)__pagable_start,
			   pagable_size);
	TEE_ASSERT(mm);
	tee_pager_add_area(mm, TEE_PAGER_AREA_RO | TEE_PAGER_AREA_X,
			   paged_store, hashes);
	tee_pager_add_pages((vaddr_t)__pagable_start,
		ROUNDUP(init_size, SMALL_PAGE_SIZE) / SMALL_PAGE_SIZE, false);
	tee_pager_add_pages((vaddr_t)__pagable_start +
				ROUNDUP(init_size, SMALL_PAGE_SIZE),
			(pagable_size - ROUNDUP(init_size, SMALL_PAGE_SIZE)) /
				SMALL_PAGE_SIZE, true);

}
#else
static void main_init_runtime(uint32_t pagable_part __unused)
{
	/*
	 * Zero BSS area. Note that globals that would normally would go
	 * into BSS which are used before this has to be put into .nozi.*
	 * to avoid getting overwritten.
	 */
	memset(__bss_start, 0, __bss_end - __bss_start);

	malloc_init(__heap1_start, __heap1_end - __heap1_start);

	/*
	 * Initialized at this stage in the pager version of this function
	 * above
	 */
	teecore_init_ta_ram();
}
#endif

#ifdef CFG_WITH_PAGER
static void main_init_thread_stacks(void)
{
	size_t n;

	/*
	 * Allocate virtual memory for thread stacks.
	 */
	for (n = 0; n < NUM_THREADS; n++) {
		tee_mm_entry_t *mm;
		vaddr_t sp;

		/* Get unmapped page at bottom of stack */
		mm = tee_mm_alloc(&tee_mm_vcore, SMALL_PAGE_SIZE);
		TEE_ASSERT(mm);
		/* Claim eventual physical page */
		tee_pager_add_pages(tee_mm_get_smem(mm), tee_mm_get_size(mm),
				    true);

		/* Allocate the actual stack */
		mm = tee_mm_alloc(&tee_mm_vcore, STACK_THREAD_SIZE);
		TEE_ASSERT(mm);
		sp = tee_mm_get_smem(mm) + tee_mm_get_bytes(mm);
		if (!thread_init_stack(n, sp))
			panic();
		/* Claim eventual physical page */
		tee_pager_add_pages(tee_mm_get_smem(mm), tee_mm_get_size(mm),
				    true);
		/* Add the area to the pager */
		tee_pager_add_area(mm, TEE_PAGER_AREA_RW, NULL, NULL);
	}
}
#else
static void main_init_thread_stacks(void)
{
	size_t n;

	/* Assign the thread stacks */
	for (n = 0; n < NUM_THREADS; n++) {
		if (!thread_init_stack(n, GET_STACK(stack_thread[n])))
			panic();
	}
}
#endif

static void main_init_primary_helper(uint32_t pagable_part, uint32_t nsec_entry)
{
	size_t pos = get_core_pos();

	/*
	 * Mask external Abort, IRQ and FIQ before switch to the thread
	 * vector as the thread handler requires externl Abort, IRQ and FIQ
	 * to be masked while executing with the temporary stack. The
	 * thread subsystem also asserts that IRQ is blocked when using
	 * most if its functions.
	 */
	write_cpsr(read_cpsr() | CPSR_FIA);

	main_init_runtime(pagable_part);

	DMSG("TEE initializing\n");

	if (!thread_init_stack(THREAD_TMP_STACK, GET_STACK(stack_tmp[pos])))
		panic();
	if (!thread_init_stack(THREAD_ABT_STACK, GET_STACK(stack_abt[pos])))
		panic();

	thread_init_handlers(&handlers);
	thread_init_per_cpu();
	main_init_sec_mon(pos, nsec_entry);

	/* Initialize canaries around the stacks */
	init_canaries();

	main_init_thread_stacks();

	main_init_gic();
	main_init_cpacr();
	main_init_nsacr();

	if (init_teecore() != TEE_SUCCESS)
		panic();
	DMSG("Primary CPU switching to normal world boot\n");
}

static void main_init_secondary_helper(uint32_t nsec_entry)
{
	size_t pos = get_core_pos();

	/*
	 * Mask external Abort, IRQ and FIQ before switch to the thread
	 * vector as the thread handler requires externl Abort, IRQ and FIQ
	 * to be masked while executing with the temporary stack. The
	 * thread subsystem also asserts that IRQ is blocked when using
	 * most if its functions.
	 */
	write_cpsr(read_cpsr() | CPSR_FIA);

	if (!thread_init_stack(THREAD_TMP_STACK, GET_STACK(stack_tmp[pos])))
		panic();
	if (!thread_init_stack(THREAD_ABT_STACK, GET_STACK(stack_abt[pos])))
		panic();

	thread_init_per_cpu();
	main_init_sec_mon(pos, nsec_entry);
	main_init_cpacr();
	main_init_nsacr();

	DMSG("Secondary CPU Switching to normal world boot\n");
}



#if defined(WITH_ARM_TRUSTED_FW)
/* called from assembly only */
uint32_t *main_init_primary(uint32_t pagable_part);
uint32_t *main_init_primary(uint32_t pagable_part)
{
	main_init_primary_helper(pagable_part, PADDR_INVALID);
	return thread_vector_table;
}
#elif defined(WITH_SEC_MON)
/* called from assembly only */
void main_init_primary(uint32_t pagable_part, uint32_t nsec_entry);
void main_init_primary(uint32_t pagable_part, uint32_t nsec_entry)
{
	main_init_primary_helper(pagable_part, nsec_entry);
}

/* called from assembly only */
void main_init_secondary(uint32_t nsec_entry);
void main_init_secondary(uint32_t nsec_entry)
{
	main_init_secondary_helper(nsec_entry);
}

#endif

static void main_fiq(void)
{
	uint32_t iar;

	DMSG("enter");

	iar = gic_read_iar();

	while (uart_have_rx_data(CONSOLE_UART_BASE)) {
		DMSG("cpu %zu: got 0x%x",
		     get_core_pos(), uart_getchar(CONSOLE_UART_BASE));
	}

	gic_write_eoir(iar);

	DMSG("return");
}

#if defined(WITH_ARM_TRUSTED_FW)
static uint32_t main_cpu_off_handler(uint32_t a0, uint32_t a1)
{
	(void)&a0;
	(void)&a1;
	/* Could stop generic timer here */
	PM_DEBUG("cpu %zu: a0 0%x", get_core_pos(), a0);
	return 0;
}

static uint32_t main_cpu_suspend_handler(uint32_t a0, uint32_t a1)
{
	(void)&a0;
	(void)&a1;
	/* Could save generic timer here */
	PM_DEBUG("cpu %zu: a0 0%x", get_core_pos(), a0);
	return 0;
}

static uint32_t main_cpu_resume_handler(uint32_t a0, uint32_t a1)
{
	(void)&a0;
	(void)&a1;
	/* Could restore generic timer here */
	PM_DEBUG("cpu %zu: a0 0%x", get_core_pos(), a0);
	return 0;
}

/* called from assembly only */
uint32_t main_cpu_on_handler(uint32_t a0, uint32_t a1);
uint32_t main_cpu_on_handler(uint32_t a0, uint32_t a1)
{
	(void)&a0;
	(void)&a1;
	PM_DEBUG("cpu %zu: a0 0%x", get_core_pos(), a0);
	main_init_secondary_helper(PADDR_INVALID);
	return 0;
}

static uint32_t main_system_off_handler(uint32_t a0, uint32_t a1)
{
	(void)&a0;
	(void)&a1;
	PM_DEBUG("cpu %zu: a0 0%x", get_core_pos(), a0);
	return 0;
}

static uint32_t main_system_reset_handler(uint32_t a0, uint32_t a1)
{
	(void)&a0;
	(void)&a1;
	PM_DEBUG("cpu %zu: a0 0%x", get_core_pos(), a0);
	return 0;
}

#elif defined(WITH_SEC_MON)
static uint32_t main_default_pm_handler(uint32_t a0, uint32_t a1)
{
	/*
	 * This function is not supported in this configuration, and
	 * should never be called. Panic to catch unintended calls.
	 */
	(void)&a0;
	(void)&a1;
	panic();
	return 1;
}
#endif

paddr_t core_mmu_get_main_ttb_pa(void)
{
	/* Note that this depends on flat mapping of TEE Core */
	paddr_t pa = (paddr_t)core_mmu_get_main_ttb_va();

	TEE_ASSERT(!(pa & ~TEE_MMU_TTB_L1_MASK));
	return pa;
}

vaddr_t core_mmu_get_main_ttb_va(void)
{
	return (vaddr_t)main_mmu_l1_ttb;
}

paddr_t core_mmu_get_ul1_ttb_pa(void)
{
	/* Note that this depends on flat mapping of TEE Core */
	paddr_t pa = (paddr_t)core_mmu_get_ul1_ttb_va();

	TEE_ASSERT(!(pa & ~TEE_MMU_TTB_UL1_MASK));
	return pa;
}

vaddr_t core_mmu_get_ul1_ttb_va(void)
{
	return (vaddr_t)main_mmu_ul1_ttb[thread_get_id()];
}

void console_putc(int ch)
{
	uart_putc(ch, CONSOLE_UART_BASE);
	if (ch == '\n')
		uart_putc('\r', CONSOLE_UART_BASE);
}

void console_flush_tx_fifo(void)
{
	uart_flush_tx_fifo(CONSOLE_UART_BASE);
}

void *core_mmu_alloc_l2(struct map_area *map)
{
	/* Can't have this in .bss since it's not initialized yet */
	static size_t l2_offs __attribute__((section(".data")));
	size_t l2_va_space = ((sizeof(main_mmu_l2_ttb) - l2_offs) /
			     TEE_MMU_L2_SIZE) * SECTION_SIZE;

	if (l2_offs)
		return NULL;
	if (map->type != MEM_AREA_TEE_RAM)
		return NULL;
	if (map->size > l2_va_space)
		return NULL;
	l2_offs += ROUNDUP(map->size, SECTION_SIZE) / SECTION_SIZE;
	return main_mmu_l2_ttb;
}

