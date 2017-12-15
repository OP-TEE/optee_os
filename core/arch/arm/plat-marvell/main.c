// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2017 Marvell International Ltd.
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
#include <console.h>
#include <drivers/gic.h>
#if defined(PLATFORM_FLAVOR_armada7k8k)
#include <drivers/serial8250_uart.h>
#elif defined(PLATFORM_FLAVOR_armada3700)
#include <drivers/mvebu_uart.h>
#endif
#include <keep.h>
#include <kernel/generic_boot.h>
#include <kernel/pm_stubs.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/tee_time.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <stdint.h>
#include <string.h>
#include <tee/entry_fast.h>
#include <tee/entry_std.h>

static void main_fiq(void);

static const struct thread_handlers handlers = {
	.std_smc = tee_entry_std,
	.fast_smc = tee_entry_fast,
	.nintr = main_fiq,
	.cpu_on = cpu_on_handler,
	.cpu_off = pm_do_nothing,
	.cpu_suspend = pm_do_nothing,
	.cpu_resume = pm_do_nothing,
	.system_off = pm_do_nothing,
	.system_reset = pm_do_nothing,
};

static struct gic_data gic_data;
#if defined(PLATFORM_FLAVOR_armada7k8k)
static struct serial8250_uart_data console_data;
#elif defined(PLATFORM_FLAVOR_armada3700)
static struct mvebu_uart_data console_data;
#endif

const struct thread_handlers *generic_boot_get_handlers(void)
{
	return &handlers;
}

register_phys_mem(MEM_AREA_IO_SEC, CONSOLE_UART_BASE, CORE_MMU_DEVICE_SIZE);

#ifdef GIC_BASE
register_phys_mem(MEM_AREA_IO_SEC, GICD_BASE, CORE_MMU_DEVICE_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, GICC_BASE, CORE_MMU_DEVICE_SIZE);

void main_init_gic(void)
{
	vaddr_t gicc_base;
	vaddr_t gicd_base;

	gicc_base = (vaddr_t)phys_to_virt(GIC_BASE + GICC_OFFSET,
					  MEM_AREA_IO_SEC);
	gicd_base = (vaddr_t)phys_to_virt(GIC_BASE + GICD_OFFSET,
					  MEM_AREA_IO_SEC);
	if (!gicc_base || !gicd_base)
		panic();

	gic_init_base_addr(&gic_data, gicc_base, gicd_base);

	itr_init(&gic_data.chip);
}
#endif

static void main_fiq(void)
{
	gic_it_handle(&gic_data);
}

void console_init(void)
{
#if defined(PLATFORM_FLAVOR_armada7k8k)
	serial8250_uart_init(&console_data, CONSOLE_UART_BASE,
		CONSOLE_UART_CLK_IN_HZ, CONSOLE_BAUDRATE);
#elif defined(PLATFORM_FLAVOR_armada3700)
	mvebu_uart_init(&console_data, CONSOLE_UART_BASE,
		CONSOLE_UART_CLK_IN_HZ, CONSOLE_BAUDRATE);
#endif
	register_serial_console(&console_data.chip);
}
