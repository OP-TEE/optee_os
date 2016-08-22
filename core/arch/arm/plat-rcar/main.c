/*
 * Copyright (c) 2016, GlobalLogic
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

#include <console.h>
#include <kernel/generic_boot.h>
#include <kernel/panic.h>
#include <kernel/pm_stubs.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>
#include <tee/entry_std.h>
#include <tee/entry_fast.h>
#include <drivers/scif.h>
#include <drivers/gic.h>

register_phys_mem(MEM_AREA_IO_SEC, CONSOLE_UART_BASE, SCIF_REG_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, GICD_BASE, GIC_DIST_REG_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, GICC_BASE, GIC_DIST_REG_SIZE);

static void main_fiq(void);

static const struct thread_handlers handlers = {
	.std_smc = tee_entry_std,
	.fast_smc = tee_entry_fast,
	.fiq = main_fiq,
	.cpu_on = cpu_on_handler,
	.cpu_off = pm_do_nothing,
	.cpu_suspend = pm_do_nothing,
	.cpu_resume = pm_do_nothing,
	.system_off = pm_do_nothing,
	.system_reset = pm_do_nothing,
};

const struct thread_handlers *generic_boot_get_handlers(void)
{
	return &handlers;
}

static void main_fiq(void)
{
	panic();
}

static vaddr_t console_base(void)
{
	static void *va;

	if (cpu_mmu_enabled()) {
		if (!va)
			va = phys_to_virt(CONSOLE_UART_BASE, MEM_AREA_IO_SEC);
		return (vaddr_t)va;
	}
	return CONSOLE_UART_BASE;
}

void console_init(void)
{
	scif_uart_init(console_base());
}

void console_putc(int ch)
{
	if (ch == '\n')
		scif_uart_putc('\r', console_base());
	scif_uart_putc(ch, console_base());
}

void console_flush(void)
{
	scif_uart_flush(console_base());
}
