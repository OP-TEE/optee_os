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
#include <stdint.h>
#include <string.h>
#include <sm/sm.h>
#include <sm/sm_defs.h>
#include <sm/tee_mon.h>
#include <sm/teesmc.h>
#include <sm/teesmc_optee.h>
#include <kernel/arch_debug.h>
#include <arm32.h>
#include <kernel/thread.h>
#include <kernel/panic.h>
#include <malloc.h>
#include <util.h>
#include <trace.h>
#include <kernel/misc.h>
#include <mm/tee_pager_unpg.h>
#include <mm/core_mmu.h>
#include <mm/tee_mmu_defs.h>
#include <tee/entry.h>
#include <console.h>
#include <kernel/asc.h>
#include <kernel/tee_l2cc_mutex.h>
#include <assert.h>

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

#define STACK_ALIGNMENT		8

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
#error "Top of tmp stacks aren't defined for more than 4 CPUS"
#endif
};

/* teecore heap address/size is defined in scatter file */
extern unsigned char teecore_heap_start;
extern unsigned char teecore_heap_end;


static void main_fiq(void);
static void main_tee_entry(struct thread_smc_args *args);
static uint32_t main_default_pm_handler(uint32_t a0, uint32_t a1);

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
	.svc = NULL, /* XXX currently using hardcod svc handler */
	.abort = tee_pager_abort_handler,
	.cpu_on = main_default_pm_handler,
	.cpu_off = main_default_pm_handler,
	.cpu_suspend = main_default_pm_handler,
	.cpu_resume = main_default_pm_handler,
	.system_off = main_default_pm_handler,
	.system_reset = main_default_pm_handler,
};

void main_init(uint32_t nsec_entry); /* called from assembly only */
void main_init(uint32_t nsec_entry)
{
	struct sm_nsec_ctx *nsec_ctx;
	size_t pos = get_core_pos();

	/*
	 * Mask IRQ and FIQ before switch to the thread vector as the
	 * thread handler requires IRQ and FIQ to be masked while executing
	 * with the temporary stack. The thread subsystem also asserts that
	 * IRQ is blocked when using most if its functions.
	 */
	write_cpsr(read_cpsr() | CPSR_F | CPSR_I);

	if (pos == 0) {
		size_t n;

		/* Initialize canries around the stacks */
		init_canaries();

		/* Assign the thread stacks */
		for (n = 0; n < NUM_THREADS; n++) {
			if (!thread_init_stack(n, GET_STACK(stack_thread[n])))
				panic();
		}
	}

	if (!thread_init_stack(THREAD_TMP_STACK, GET_STACK(stack_tmp[pos])))
		panic();
	if (!thread_init_stack(THREAD_ABT_STACK, GET_STACK(stack_abt[pos])))
		panic();

	thread_init_handlers(&handlers);

	/* Initialize secure monitor */
	sm_init(GET_STACK(stack_sm[pos]));
	nsec_ctx = sm_get_nsec_ctx();
	nsec_ctx->mon_lr = nsec_entry;
	nsec_ctx->mon_spsr = CPSR_MODE_SVC | CPSR_I;
	sm_set_entry_vector(thread_vector_table);

	if (pos == 0) {
		unsigned long a, s;
		/* core malloc pool init */
#ifdef CFG_TEE_MALLOC_START
		a = CFG_TEE_MALLOC_START;
		s = CFG_TEE_MALLOC_SIZE;
#else
		a = (unsigned long)&teecore_heap_start;
		s = (unsigned long)&teecore_heap_end;
		a = ((a + 1) & ~0x0FFFF) + 0x10000;	/* 64kB aligned */
		s = s & ~0x0FFFF;	/* 64kB aligned */
		s = s - a;
#endif
		malloc_init((void *)a, s);
	}
}

static void main_fiq(void)
{
	panic();
}

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

static void main_tee_entry(struct thread_smc_args *args)
{
	/*
	 * This function first catches all ST specific SMC functions
	 * if none matches, the generic tee_entry is called.
	 */
	int ret;

	/* TODO move to main_init() */
	if (init_teecore() != TEE_SUCCESS)
		panic();

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
			ret = tee_l2cc_mutex_configure(
					SERVICEID_GET_L2CC_MUTEX, &args->a2);
			break;
		case TEESMC_OPTEE_L2CC_MUTEX_SET_ADDR:
			ret = tee_l2cc_mutex_configure(
					SERVICEID_SET_L2CC_MUTEX, &args->a2);
			break;
		case TEESMC_OPTEE_L2CC_MUTEX_ENABLE:
			ret = tee_l2cc_mutex_configure(
					SERVICEID_ENABLE_L2CC_MUTEX, NULL);
			break;
		case TEESMC_OPTEE_L2CC_MUTEX_DISABLE:
			ret = tee_l2cc_mutex_configure(
					SERVICEID_DISABLE_L2CC_MUTEX, NULL);
			break;
		default:
			args->a0 = TEESMC_RETURN_EBADCMD;
			return;
		}
		if (ret)
			args->a0 = TEESMC_RETURN_EBADADDR;
		else
			args->a0 = TEESMC_RETURN_OK;
		return;
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

extern uint8_t *SEC_MMU_TTB_FLD;
extern uint8_t *SEC_TA_MMU_TTB_FLD[CFG_TEE_CORE_NB_CORE][TEE_MMU_UL1_NUM_ENTRIES];

paddr_t core_mmu_get_main_ttb_pa(void)
{
	/* Note that this depends on flat mapping of TEE Core */
	paddr_t pa = (paddr_t)core_mmu_get_main_ttb_va();

	TEE_ASSERT(!(pa & ~TEE_MMU_TTB_L1_MASK));
	return pa;
}

vaddr_t core_mmu_get_main_ttb_va(void)
{
	return (vaddr_t)&SEC_MMU_TTB_FLD;
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
	return (vaddr_t)SEC_TA_MMU_TTB_FLD +
		thread_get_id() * TEE_MMU_UL1_NUM_ENTRIES;
}

void console_putc(int ch)
{
	__asc_xmit_char((char)ch);
}

void console_flush_tx_fifo(void)
{
	__asc_flush();
}
