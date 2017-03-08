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

#include <arm.h>
#include <assert.h>
#include <console.h>
#include <drivers/sunxi_uart.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/pm_stubs.h>
#include <kernel/thread.h>
#include <kernel/time_source.h>
#include <malloc.h>
#include <mm/core_mmu.h>
#include <mm/tee_mmu.h>
#include <optee_msg.h>
#include <platform_config.h>
#include <platform.h>
#include <sm/optee_smc.h>
#include <sm/sm.h>
#include <sm/tee_mon.h>
#include <stdint.h>
#include <string.h>
#include <tee/entry_fast.h>
#include <tee/entry_std.h>
#include <trace.h>
#include <util.h>

/* teecore heap address/size is defined in scatter file */
extern unsigned char teecore_heap_start;
extern unsigned char teecore_heap_end;

static void main_fiq(void);
static void main_tee_entry_std(struct thread_smc_args *args);
static void main_tee_entry_fast(struct thread_smc_args *args);

static const struct thread_handlers handlers = {
	.std_smc = main_tee_entry_std,
	.fast_smc = main_tee_entry_fast,
	.nintr = main_fiq,
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
	 * Mask the interrupts before switch to the thread vector as the
	 * thread handler requires the interrupts to be masked while executing
	 * with the temporary stack. The thread subsystem also asserts that
	 * foreign interrupts are blocked when using most if its functions.
	 */
	thread_mask_exceptions(
			THREAD_EXCP_NATIVE_INTR | THREAD_EXCP_FOREIGN_INTR);

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
		malloc_add_pool((void *)a, s);

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

static void main_tee_entry_fast(struct thread_smc_args *args)
{
	/* TODO move to main_init() */
	if (init_teecore() != TEE_SUCCESS)
		panic();

	/* SiP Service Call Count */
	if (args->a0 == OPTEE_SMC_SIP_SUNXI_CALLS_COUNT) {
		args->a0 = 1;
		return;
	}

	/*  SiP Service Call UID */
	if (args->a0 == OPTEE_SMC_SIP_SUNXI_CALLS_UID) {
		args->a0 = OPTEE_SMC_SIP_SUNXI_UID_R0;
		args->a1 = OPTEE_SMC_SIP_SUNXI_UID_R1;
		args->a2 = OPTEE_SMC_SIP_SUNXI_UID_R2;
		args->a3 = OPTEE_SMC_SIP_SUNXI_UID_R3;
		return;
	}

	/* SiP Service Calls */
	if (args->a0 == OPTEE_SMC_OPTEE_FAST_CALL_SIP_SUNXI) {
		platform_smc_handle(args);
		return;
	}

	tee_entry_fast(args);
}



static void main_tee_entry_std(struct thread_smc_args *args)
{
	/* TODO move to main_init() */
	if (init_teecore() != TEE_SUCCESS)
		panic();

	tee_entry_std(args);
}

/* main_tee_entry_fast() supports 3 platform-specific functions */
void tee_entry_get_api_call_count(struct thread_smc_args *args)
{
	args->a0 = tee_entry_generic_get_api_call_count() + 3;
}

static struct sunxi_uart_data console_data;

void console_init(void)
{
	sunxi_uart_init(&console_data, CONSOLE_UART_BASE);
	register_serial_console(&console_data.chip);
}
