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
#include <sm/teesmc.h>
#include <sm/teesmc_optee.h>

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
#include <mm/tee_mmu.h>
#include <mm/tee_mmu_defs.h>
#include <tee/entry.h>
#include <tee/arch_svc.h>
#include <console.h>
#include <malloc.h>

#include <assert.h>

#define NSEC_ENTRY_INVALID	0xffffffff

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
	static uint32_t name[num_stacks][(stack_size + STACK_CANARY_SIZE) / \
					 sizeof(uint32_t)] \
		__attribute__((section(".nozi.stack"), \
			       aligned(STACK_ALIGNMENT)))

#define GET_STACK(stack) \
	((vaddr_t)(stack) + sizeof(stack) - STACK_CANARY_SIZE / 2)


DECLARE_STACK(stack_tmp,	CFG_TEE_CORE_NB_CORE,	STACK_TMP_SIZE);
DECLARE_STACK(stack_abt,	CFG_TEE_CORE_NB_CORE,	STACK_ABT_SIZE);
DECLARE_STACK(stack_sm,		CFG_TEE_CORE_NB_CORE,	SM_STACK_SIZE);
DECLARE_STACK(stack_thread,	NUM_THREADS,		STACK_THREAD_SIZE);

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

extern uint8_t __text_start;
extern uint8_t __rodata_end;
extern uint8_t __data_start;
extern uint8_t __bss_start;
extern uint8_t __bss_end;
extern uint8_t _end;
extern uint8_t _end_of_ram;
extern uint8_t __heap_start;
extern uint8_t __heap_end;
extern uint8_t __nozi_pad_start;
extern uint8_t __nozi_pad_end;

static void main_fiq(void);
static void main_tee_entry(struct thread_smc_args *args);
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
	INIT_CANARY(stack_thread);
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
	ASSERT_STACK_CANARIES(stack_thread);
#endif /*WITH_STACK_CANARIES*/
}

static const struct thread_handlers handlers = {
	.std_smc = main_tee_entry,
	.fast_smc = main_tee_entry,
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
	assert(nsec_entry == NSEC_ENTRY_INVALID);
	/* Do nothing as we don't have a secure monitor */
}
#elif defined(WITH_SEC_MON)
static void main_init_sec_mon(size_t pos, uint32_t nsec_entry)
{
	struct sm_nsec_ctx *nsec_ctx;

	assert(nsec_entry != NSEC_ENTRY_INVALID);

	/* Initialize secure monitor */
	sm_init(GET_STACK(stack_sm[pos]));
	nsec_ctx = sm_get_nsec_ctx();
	nsec_ctx->mon_lr = nsec_entry;
	nsec_ctx->mon_spsr = CPSR_MODE_SVC | CPSR_I;
	sm_set_entry_vector(thread_vector_table);

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

static void main_init_helper(bool is_primary, size_t pos, uint32_t nsec_entry)
{

	/*
	 * Mask external Abort, IRQ and FIQ before switch to the thread
	 * vector as the thread handler requires externl Abort, IRQ and FIQ
	 * to be masked while executing with the temporary stack. The
	 * thread subsystem also asserts that IRQ is blocked when using
	 * most if its functions.
	 */
	write_cpsr(read_cpsr() | CPSR_FIA);

	if (is_primary) {
		uintptr_t bss_start = (uintptr_t)&__bss_start;
		uintptr_t bss_end = (uintptr_t)&__bss_end;
		size_t n;

		/* Initialize uart with virtual address */
		uart_init(CONSOLE_UART_BASE, CONSOLE_UART_CLK_IN_HZ,
			  CONSOLE_BAUDRATE);

		/*
		 * Zero BSS area. Note that globals that would normally
		 * would go into BSS which are used before this has to be
		 * put into .nozi.* to avoid getting overwritten.
		 */
		memset((void *)bss_start, 0, bss_end - bss_start);

		DMSG("TEE initializing\n");

		/* Initialize canaries around the stacks */
		init_canaries();

		/* Assign the thread stacks */
		for (n = 0; n < NUM_THREADS; n++) {
			if (!thread_init_stack(n, GET_STACK(stack_thread[n])))
				panic();
		}

		thread_init_handlers(&handlers);
	}

	if (!thread_init_stack(THREAD_TMP_STACK, GET_STACK(stack_tmp[pos])))
		panic();
	if (!thread_init_stack(THREAD_ABT_STACK, GET_STACK(stack_abt[pos])))
		panic();

	thread_init_per_cpu();

	main_init_sec_mon(pos, nsec_entry);

	if (is_primary) {
		main_init_gic();

		malloc_init(&__heap_start,
				(uintptr_t)&__heap_end -
					(uintptr_t)&__heap_start);
		malloc_add_pool(&__nozi_pad_start,
				(uintptr_t)&__nozi_pad_end -
					(uintptr_t)&__nozi_pad_start);

		teecore_init_ta_ram();
		if (init_teecore() != TEE_SUCCESS)
			panic();
		DMSG("Primary CPU switching to normal world boot\n");
	} else {
		DMSG("Secondary CPU Switching to normal world boot\n");
	}
}

#if defined(WITH_ARM_TRUSTED_FW)
uint32_t *main_init(void); /* called from assembly only */
uint32_t *main_init(void)
{
	main_init_helper(true, get_core_pos(), NSEC_ENTRY_INVALID);
	return thread_vector_table;
}
#elif defined(WITH_SEC_MON)
void main_init(uint32_t nsec_entry); /* called from assembly only */
void main_init(uint32_t nsec_entry)
{
	size_t pos = get_core_pos();

	main_init_helper(pos == 0, pos, nsec_entry);
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
	size_t pos = get_core_pos();

	(void)&a0;
	(void)&a1;
	PM_DEBUG("cpu %zu: a0 0%x", pos, a0);
	main_init_helper(false, pos, NSEC_ENTRY_INVALID);
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

static void main_tee_entry(struct thread_smc_args *args)
{
	/*
	 * This function first catches all ST specific SMC functions
	 * if none matches, the generic tee_entry is called.
	 */

	if (args->a0 == TEESMC32_OPTEE_FASTCALL_GET_SHM_CONFIG) {
		args->a0 = TEESMC_RETURN_OK;
		args->a1 = default_nsec_shm_paddr;
		args->a2 = default_nsec_shm_size;
		/* Should this be TEESMC cache attributes instead? */
		args->a3 = core_mmu_is_shm_cached();
		return;
	}

	if (args->a0 == TEESMC32_OPTEE_FASTCALL_L2CC_MUTEX) {
		switch (args->a1) {
		case TEESMC_OPTEE_L2CC_MUTEX_GET_ADDR:
		case TEESMC_OPTEE_L2CC_MUTEX_SET_ADDR:
		case TEESMC_OPTEE_L2CC_MUTEX_ENABLE:
		case TEESMC_OPTEE_L2CC_MUTEX_DISABLE:
			/* TODO call the appropriate internal functions */
			args->a0 = TEESMC_RETURN_UNKNOWN_FUNCTION;
			return;
		default:
			args->a0 = TEESMC_RETURN_EBADCMD;
			return;
		}
	}

	tee_entry(args);
}



/* Override weak function in tee/entry.c */
void tee_entry_get_api_call_count(struct thread_smc_args *args)
{
	args->a0 = tee_entry_generic_get_api_call_count() + 2;
}

/* Override weak function in tee/entry.c */
void tee_entry_get_api_uuid(struct thread_smc_args *args)
{
	args->a0 = TEESMC_OPTEE_UID_R0;
	args->a1 = TEESMC_OPTEE_UID_R1;
	args->a2 = TEESMC_OPTEE_UID_R2;
	args->a3 = TEESMC_OPTEE_UID32_R3;
}

/* Override weak function in tee/entry.c */
void tee_entry_get_api_revision(struct thread_smc_args *args)
{
	args->a0 = TEESMC_OPTEE_REVISION_MAJOR;
	args->a1 = TEESMC_OPTEE_REVISION_MINOR;
}

/* Override weak function in tee/entry.c */
void tee_entry_get_os_uuid(struct thread_smc_args *args)
{
	args->a0 = TEESMC_OS_OPTEE_UUID_R0;
	args->a1 = TEESMC_OS_OPTEE_UUID_R1;
	args->a2 = TEESMC_OS_OPTEE_UUID_R2;
	args->a3 = TEESMC_OS_OPTEE_UUID_R3;
}

/* Override weak function in tee/entry.c */
void tee_entry_get_os_revision(struct thread_smc_args *args)
{
	args->a0 = TEESMC_OS_OPTEE_REVISION_MAJOR;
	args->a1 = TEESMC_OS_OPTEE_REVISION_MINOR;
}

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
