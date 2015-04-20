/*
 * Copyright (c) 2014, Allwinner Technology Co., Ltd.
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

#include <stdint.h>
#include <string.h>
#include <assert.h>

#include <sm/sm.h>
#include <sm/tee_mon.h>
#include <sm/teesmc.h>
#include <sm/teesmc_optee.h>

#include <arm.h>
#include <kernel/thread.h>
#include <kernel/time_source.h>
#include <kernel/panic.h>
#include <kernel/misc.h>
#include <mm/tee_pager.h>
#include <mm/tee_mmu.h>
#include <mm/core_mmu.h>
#include <mm/tee_mmu_defs.h>
#include <pm/pm.h>
#include <tee/entry.h>
#include <tee/arch_svc.h>
#include <platform.h>
#include <util.h>
#include <trace.h>
#include <malloc.h>

/* teecore heap address/size is defined in scatter file */
extern unsigned char teecore_heap_start;
extern unsigned char teecore_heap_end;

static void main_fiq(void);
static void main_tee_entry(struct thread_smc_args *args);

static const struct thread_handlers handlers = {
	.std_smc = main_tee_entry,
	.fast_smc = main_tee_entry,
	.fiq = main_fiq,
	.svc = tee_svc_handler,
	.abort = tee_pager_abort_handler,
	.cpu_on = pm_panic,
	.cpu_off = pm_panic,
	.cpu_suspend = pm_panic,
	.cpu_resume = pm_panic,
	.system_off = pm_panic,
	.system_reset = pm_panic,
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
		thread_init_primary(&handlers);

		/* initialize platform */
		platform_init();
	}

	thread_init_per_cpu();

	/* Initialize secure monitor */
	nsec_ctx = sm_get_nsec_ctx();
	nsec_ctx->mon_lr = nsec_entry;
	nsec_ctx->mon_spsr = CPSR_MODE_SVC | CPSR_I;

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

		teecore_init_ta_ram();

		if (init_teecore() != TEE_SUCCESS) {
			panic();
		}
	}

	IMSG("optee initialize finished\n");
}

static void main_fiq(void)
{
	panic();
}

static void main_tee_entry(struct thread_smc_args *args)
{
	/* TODO move to main_init() */
	if (init_teecore() != TEE_SUCCESS)
		panic();

	/*
	 * This function first catches platform specific SMC functions
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
			/* A80 platform not support L2CC_MUTEX */
			args->a0 = TEESMC_RETURN_UNKNOWN_FUNCTION;
			return;
		default:
			args->a0 = TEESMC_RETURN_EBADCMD;
			return;
		}
	}

	/* SiP Service Call Count */
	if (args->a0 == TEESMC32_SIP_SUNXI_CALLS_COUNT) {
		args->a0 = 1;
		return;
	}

	/*  SiP Service Call UID */
	if (args->a0 == TEESMC32_SIP_SUNXI_CALLS_UID) {
		args->a0 = TEESMC_SIP_SUNXI_UID_R0;
		args->a1 = TEESMC_SIP_SUNXI_UID_R1;
		args->a2 = TEESMC_SIP_SUNXI_UID_R2;
		args->a3 = TEESMC_SIP_SUNXI_UID_R3;
		return;
	}

	/* SiP Service Calls */
	if (args->a0 == TEESMC32_OPTEE_FAST_CALL_SIP_SUNXI) {
		platform_smc_handle(args);
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
