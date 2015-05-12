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
#include <sm/tee_mon.h>
#include <sm/teesmc.h>
#include <sm/teesmc_optee.h>
#include <arm.h>
#include <kernel/thread.h>
#include <kernel/panic.h>
#include <kernel/pm_stubs.h>
#include <malloc.h>
#include <util.h>
#include <trace.h>
#include <kernel/misc.h>
#include <mm/tee_pager.h>
#include <mm/core_mmu.h>
#include <mm/tee_mmu.h>
#include <mm/tee_mmu_defs.h>
#include <tee/entry.h>
#include <tee/arch_svc.h>
#include <console.h>
#include <asc.h>
#include <assert.h>
#include <platform_config.h>

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

#define PADDR_INVALID		0xffffffff

/* May be overridden in plat-$(PLATFORM)/main.c */
void main_init_gic(void);
__weak void main_init_gic(void)
{
}

#if defined(CFG_WITH_ARM_TRUSTED_FW)
static void init_sec_mon(uint32_t nsec_entry __unused)
{
	assert(nsec_entry == PADDR_INVALID);
	/* Do nothing as we don't have a secure monitor */
}
#else
static void init_sec_mon(uint32_t nsec_entry)
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
static void init_nsacr(void)
{
}
#else
static void init_nsacr(void)
{
	/* Normal world can use CP10 and CP11 (SIMD/VFP) */
	write_nsacr(read_nsacr() | NSACR_CP10 | NSACR_CP11);
}
#endif

#ifdef CFG_WITH_VFP
static void init_cpacr(void)
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
static void init_cpacr(void)
{
	/* We're not using VFP/SIMD instructions, leave it disabled */
}
#endif

static void init_primary_helper(uint32_t nsec_entry)
{
	/*
	 * Mask asynchronous exceptions before switch to the thread vector
	 * as the thread handler requires those to be masked while
	 * executing with the temporary stack. The thread subsystem also
	 * asserts that IRQ is blocked when using most if its functions.
	 */
	thread_set_exceptions(THREAD_EXCP_ALL);
	init_cpacr();

	/* init_runtime(pageable_part); */

	DMSG("TEE initializing\n");

	thread_init_primary(&handlers);
	thread_init_per_cpu();
	init_sec_mon(nsec_entry);


	main_init_gic();
	init_nsacr();

	{
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
	}
}

static void init_secondary_helper(uint32_t nsec_entry)
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
	init_cpacr();
	init_nsacr();

	DMSG("Secondary CPU Switching to normal world boot\n");
}

#if defined(CFG_WITH_ARM_TRUSTED_FW)
uint32_t *generic_boot_init_primary(uint32_t pageable_part)
{
	init_primary_helper(pageable_part, PADDR_INVALID);
	return thread_vector_table;
}

uint32_t generic_boot_cpu_on_handler(uint32_t a0 __unused, uint32_t a1 __unused)
{
	DMSG("cpu %zu: a0 0x%x", get_core_pos(), a0);
	init_secondary_helper(PADDR_INVALID);
	return 0;
}
#else
void generic_boot_init_primary(uint32_t nsec_entry);
void generic_boot_init_primary(uint32_t nsec_entry)
{
	init_primary_helper(nsec_entry);
}

void generic_boot_init_secondary(uint32_t nsec_entry);
void generic_boot_init_secondary(uint32_t nsec_entry)
{
	init_secondary_helper(nsec_entry);
}
#endif

static void main_fiq(void)
{
	panic();
}

static void main_tee_entry(struct thread_smc_args *args)
{
	/* TODO move to main_init() */
	if (init_teecore() != TEE_SUCCESS)
		panic();

	tee_entry(args);
}

void console_putc(int ch)
{
	__asc_xmit_char((char)ch);
}

void console_flush(void)
{
	__asc_flush();
}
