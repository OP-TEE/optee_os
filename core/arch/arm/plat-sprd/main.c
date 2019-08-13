// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Spreadtrum Communications Inc.
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

#include <drivers/gic.h>
#include <kernel/generic_boot.h>
#include <kernel/panic.h>
#include <kernel/pm_stubs.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <trace.h>
#include <tee/entry_fast.h>
#include <tee/entry_std.h>

register_phys_mem_pgdir(MEM_AREA_IO_NSEC,
			ROUNDDOWN(CONSOLE_UART_BASE, CORE_MMU_PGDIR_SIZE),
			CORE_MMU_PGDIR_SIZE);

register_phys_mem_pgdir(MEM_AREA_IO_SEC,
			ROUNDDOWN(GIC_BASE, CORE_MMU_PGDIR_SIZE),
			CORE_MMU_PGDIR_SIZE);

register_phys_mem_pgdir(MEM_AREA_IO_SEC,
			ROUNDDOWN(GIC_BASE + GICD_OFFSET, CORE_MMU_PGDIR_SIZE),
			CORE_MMU_PGDIR_SIZE);

static void main_fiq(void);

static const struct thread_handlers handlers = {
	.nintr = main_fiq,
	.cpu_on = cpu_on_handler,
	.cpu_off = pm_do_nothing,
	.cpu_suspend = pm_do_nothing,
	.cpu_resume = pm_do_nothing,
	.system_off = pm_do_nothing,
	.system_reset = pm_do_nothing,
};

static struct gic_data gic_data;

const struct thread_handlers *generic_boot_get_handlers(void)
{
	return &handlers;
}

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

static void main_fiq(void)
{
	gic_it_handle(&gic_data);
}
