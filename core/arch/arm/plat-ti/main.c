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

#include <platform_config.h>
#include <console.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <drivers/gic.h>
#include <drivers/serial8250_uart.h>
#include <arm.h>
#include <kernel/generic_boot.h>
#include <kernel/panic.h>
#include <kernel/pm_stubs.h>
#include <trace.h>
#include <kernel/misc.h>
#include <kernel/mutex.h>
#include <kernel/tee_time.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <tee/entry_std.h>
#include <tee/entry_fast.h>
#include <console.h>
#include <sm/sm.h>

static struct gic_data gic_data;
static struct serial8250_uart_data console_data __early_bss;

register_phys_mem(MEM_AREA_IO_SEC, GICC_BASE, GICC_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, GICD_BASE, GICD_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, CONSOLE_UART_BASE,
		  SERIAL8250_UART_REG_SIZE);

void main_init_gic(void)
{
	vaddr_t gicc_base;
	vaddr_t gicd_base;

	gicc_base = (vaddr_t)phys_to_virt(GICC_BASE, MEM_AREA_IO_SEC);
	gicd_base = (vaddr_t)phys_to_virt(GICD_BASE, MEM_AREA_IO_SEC);

	if (!gicc_base || !gicd_base)
		panic();

	gic_init(&gic_data, gicc_base, gicd_base);
	itr_init(&gic_data.chip);
}

void main_secondary_init_gic(void)
{
	gic_cpu_init(&gic_data);
}

static void main_fiq(void)
{
	gic_it_handle(&gic_data);
}

static const struct thread_handlers handlers = {
	.std_smc = tee_entry_std,
	.fast_smc = tee_entry_fast,
	.nintr = main_fiq,
	.cpu_on = pm_panic,
	.cpu_off = pm_panic,
	.cpu_suspend = pm_panic,
	.cpu_resume = pm_panic,
	.system_off = pm_panic,
	.system_reset = pm_panic,
};

const struct thread_handlers *generic_boot_get_handlers(void)
{
	return &handlers;
}

struct plat_nsec_ctx {
	uint32_t usr_sp;
	uint32_t usr_lr;
	uint32_t svc_sp;
	uint32_t svc_lr;
	uint32_t svc_spsr;
	uint32_t abt_sp;
	uint32_t abt_lr;
	uint32_t abt_spsr;
	uint32_t und_sp;
	uint32_t und_lr;
	uint32_t und_spsr;
	uint32_t irq_sp;
	uint32_t irq_lr;
	uint32_t irq_spsr;
	uint32_t fiq_sp;
	uint32_t fiq_lr;
	uint32_t fiq_spsr;
	uint32_t fiq_rx[5];
	uint32_t mon_lr;
	uint32_t mon_spsr;
};

void init_sec_mon(unsigned long nsec_entry)
{
	struct plat_nsec_ctx *plat_ctx;
	struct sm_nsec_ctx *nsec_ctx;

	plat_ctx = phys_to_virt(nsec_entry, MEM_AREA_IO_SEC);
	if (!plat_ctx)
		panic();

	/* Invalidate cache to fetch data from external memory */
	cache_op_inner(DCACHE_AREA_INVALIDATE,
			plat_ctx, sizeof(*plat_ctx));

	/* Initialize secure monitor */
	nsec_ctx = sm_get_nsec_ctx();

	nsec_ctx->mode_regs.usr_sp = plat_ctx->usr_sp;
	nsec_ctx->mode_regs.usr_lr = plat_ctx->usr_lr;
	nsec_ctx->mode_regs.irq_spsr = plat_ctx->irq_spsr;
	nsec_ctx->mode_regs.irq_sp = plat_ctx->irq_sp;
	nsec_ctx->mode_regs.irq_lr = plat_ctx->irq_lr;
	nsec_ctx->mode_regs.svc_spsr = plat_ctx->svc_spsr;
	nsec_ctx->mode_regs.svc_sp = plat_ctx->svc_sp;
	nsec_ctx->mode_regs.svc_lr = plat_ctx->svc_lr;
	nsec_ctx->mode_regs.abt_spsr = plat_ctx->abt_spsr;
	nsec_ctx->mode_regs.abt_sp = plat_ctx->abt_sp;
	nsec_ctx->mode_regs.abt_lr = plat_ctx->abt_lr;
	nsec_ctx->mode_regs.und_spsr = plat_ctx->und_spsr;
	nsec_ctx->mode_regs.und_sp = plat_ctx->und_sp;
	nsec_ctx->mode_regs.und_lr = plat_ctx->und_lr;
	nsec_ctx->mon_lr = plat_ctx->mon_lr;
	nsec_ctx->mon_spsr = plat_ctx->mon_spsr;
}

void console_init(void)
{
	serial8250_uart_init(&console_data, CONSOLE_UART_BASE,
			     CONSOLE_UART_CLK_IN_HZ, CONSOLE_BAUDRATE);
	register_serial_console(&console_data.chip);
}
