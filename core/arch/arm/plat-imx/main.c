/*
 * Copyright (C) 2015 Freescale Semiconductor, Inc.
 * All rights reserved.
 * Copyright (c) 2016, Wind River Systems.
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
#include <drivers/imx_uart.h>
#include <io.h>
#include <kernel/generic_boot.h>
#include <kernel/panic.h>
#include <kernel/pm_stubs.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>
#include <sm/optee_smc.h>
#include <tee/entry_std.h>
#include <tee/entry_fast.h>

#if defined(PLATFORM_FLAVOR_mx6qsabrelite) || \
	defined(PLATFORM_FLAVOR_mx6qsabresd)
#include <drivers/gic.h>
#include <kernel/tz_ssvce_pl310.h>
#endif

static void main_fiq(void);
static void platform_tee_entry_fast(struct thread_smc_args *args);

static const struct thread_handlers handlers = {
	.std_smc = tee_entry_std,
	.fast_smc = platform_tee_entry_fast,
	.fiq = main_fiq,
	.cpu_on = pm_panic,
	.cpu_off = pm_panic,
	.cpu_suspend = pm_panic,
	.cpu_resume = pm_panic,
	.system_off = pm_panic,
	.system_reset = pm_panic,
};

#if defined(PLATFORM_FLAVOR_mx6qsabrelite) || \
	defined(PLATFORM_FLAVOR_mx6qsabresd)
static struct gic_data gic_data;

register_phys_mem(MEM_AREA_IO_NSEC, CONSOLE_UART_BASE, CORE_MMU_DEVICE_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, GIC_BASE, CORE_MMU_DEVICE_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, PL310_BASE, CORE_MMU_DEVICE_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, SRC_BASE, CORE_MMU_DEVICE_SIZE);
#endif

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
			va = phys_to_virt(CONSOLE_UART_PA_BASE,
					  MEM_AREA_IO_NSEC);
		return (vaddr_t)va;
	}
	return CONSOLE_UART_BASE;
}

void console_init(void)
{
	vaddr_t base = console_base();

	imx_uart_init(base);
}

void console_putc(int ch)
{
	vaddr_t base = console_base();

	/* If \n, also do \r */
	if (ch == '\n')
		imx_uart_putc('\r', base);
	imx_uart_putc(ch, base);
}

void console_flush(void)
{
	vaddr_t base = console_base();

	imx_uart_flush_tx_fifo(base);
}

#if defined(PLATFORM_FLAVOR_mx6qsabrelite) || \
	defined(PLATFORM_FLAVOR_mx6qsabresd)
#ifdef CFG_BOOT_SECONDARY_REQUEST
static vaddr_t src_base(void)
{
	static void *va __data; /* in case it's used before .bss is cleared */

	if (cpu_mmu_enabled()) {
		if (!va)
			va = phys_to_virt(SRC_BASE, MEM_AREA_IO_SEC);
		return (vaddr_t)va;
	}
	return SRC_BASE;
}

static int platform_smp_boot(size_t core_idx, uint32_t entry)
{
	uint32_t val;
	vaddr_t va = src_base();

	if ((core_idx == 0) || (core_idx >= CFG_TEE_CORE_NB_CORE))
		return OPTEE_SMC_RETURN_EBADCMD;

	/* set secondary cores' NS entry addresses */

	ns_entry_addrs[core_idx] = entry;
	cache_maintenance_l1(DCACHE_AREA_CLEAN,
		&ns_entry_addrs[core_idx],
		sizeof(uint32_t));
	cache_maintenance_l2(L2CACHE_AREA_CLEAN,
		(paddr_t)&ns_entry_addrs[core_idx],
		sizeof(uint32_t));

	/* boot secondary cores from OP-TEE load address */

	write32((uint32_t)CFG_TEE_LOAD_ADDR, va + SRC_GPR1 + core_idx * 8);

	/* release secondary core */

	val = read32(va + SRC_SCR);
	val = val | BIT32(SRC_SCR_ENABLE_OFFSET + (core_idx - 1));
	write32(val, va + SRC_SCR);
	return OPTEE_SMC_RETURN_OK;
}
#endif /* CFG_BOOT_SECONDARY_REQUEST */

vaddr_t pl310_base(void)
{
	static void *va __data; /* in case it's used before .bss is cleared */

	if (cpu_mmu_enabled()) {
		if (!va)
			va = phys_to_virt(PL310_BASE, MEM_AREA_IO_SEC);
		return (vaddr_t)va;
	}
	return PL310_BASE;
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

	/* Initialize GIC */
	gic_init(&gic_data, gicc_base, gicd_base);

	itr_init(&gic_data.chip);
}
#endif

static void platform_tee_entry_fast(struct thread_smc_args *args)
{
#ifdef CFG_BOOT_SECONDARY_REQUEST
	if (args->a0 == OPTEE_SMC_BOOT_SECONDARY) {
		args->a0 = platform_smp_boot(args->a1, (uint32_t)(args->a3));
		return;
	}
#endif /* CFG_BOOT_SECONDARY_REQUEST */
	tee_entry_fast(args);
}
