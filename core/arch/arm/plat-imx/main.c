// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2015 Freescale Semiconductor, Inc.
 * Copyright (c) 2016, Wind River Systems.
 * All rights reserved.
 * Copyright 2018 NXP
 */

#include <arm.h>
#include <console.h>
#include <drivers/gic.h>
#include <drivers/imx_uart.h>
#include <io.h>
#include <imx.h>
#include <kernel/generic_boot.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/pm_stubs.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>
#include <sm/optee_smc.h>
#include <tee/entry_fast.h>
#include <tee/entry_std.h>


static void main_fiq(void);
static struct gic_data gic_data;

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

static struct imx_uart_data console_data;

#ifdef CONSOLE_UART_BASE
register_phys_mem(MEM_AREA_IO_NSEC, CONSOLE_UART_BASE, CORE_MMU_DEVICE_SIZE);
#endif
#ifdef GIC_BASE
register_phys_mem(MEM_AREA_IO_SEC, GIC_BASE, CORE_MMU_DEVICE_SIZE);
#endif
#ifdef ANATOP_BASE
register_phys_mem(MEM_AREA_IO_SEC, ANATOP_BASE, CORE_MMU_DEVICE_SIZE);
#endif
#ifdef GICD_BASE
register_phys_mem(MEM_AREA_IO_SEC, GICD_BASE, 0x10000);
#endif
#ifdef AIPS1_BASE
register_phys_mem(MEM_AREA_IO_SEC, AIPS1_BASE,
		  ROUNDUP(AIPS1_SIZE, CORE_MMU_DEVICE_SIZE));
#endif
#ifdef AIPS2_BASE
register_phys_mem(MEM_AREA_IO_SEC, AIPS2_BASE,
		  ROUNDUP(AIPS2_SIZE, CORE_MMU_DEVICE_SIZE));
#endif
#ifdef AIPS3_BASE
register_phys_mem(MEM_AREA_IO_SEC, AIPS3_BASE,
		  ROUNDUP(AIPS3_SIZE, CORE_MMU_DEVICE_SIZE));
#endif
#ifdef IRAM_BASE
register_phys_mem(MEM_AREA_TEE_COHERENT,
		  ROUNDDOWN(IRAM_BASE, CORE_MMU_DEVICE_SIZE),
		  CORE_MMU_DEVICE_SIZE);
#endif
#ifdef IRAM_S_BASE
register_phys_mem(MEM_AREA_TEE_COHERENT,
		  ROUNDDOWN(IRAM_S_BASE, CORE_MMU_DEVICE_SIZE),
		  CORE_MMU_DEVICE_SIZE);
#endif

#if defined(CFG_PL310)
register_phys_mem(MEM_AREA_IO_SEC,
		  ROUNDDOWN(PL310_BASE, CORE_MMU_DEVICE_SIZE),
		  CORE_MMU_DEVICE_SIZE);
#endif

const struct thread_handlers *generic_boot_get_handlers(void)
{
	return &handlers;
}

static void main_fiq(void)
{
	gic_it_handle(&gic_data);
}

void console_init(void)
{
	imx_uart_init(&console_data, CONSOLE_UART_BASE);
	register_serial_console(&console_data.chip);
}

void main_init_gic(void)
{
	vaddr_t gicc_base;
	vaddr_t gicd_base;

	gicc_base = core_mmu_get_va(GIC_BASE + GICC_OFFSET, MEM_AREA_IO_SEC);
	gicd_base = core_mmu_get_va(GIC_BASE + GICD_OFFSET, MEM_AREA_IO_SEC);

	if (!gicc_base || !gicd_base)
		panic();

	/* Initialize GIC */
	gic_init(&gic_data, gicc_base, gicd_base);
	itr_init(&gic_data.chip);
}

#if defined(CFG_MX6QP) || defined(CFG_MX6Q) || defined(CFG_MX6D) || \
	defined(CFG_MX6DL) || defined(CFG_MX7)
void main_secondary_init_gic(void)
{
	gic_cpu_init(&gic_data);
}
#endif

#if defined(CFG_BOOT_SYNC_CPU)
void psci_boot_allcpus(void)
{
	vaddr_t src_base = core_mmu_get_va(SRC_BASE, MEM_AREA_TEE_COHERENT);
	uint32_t pa = virt_to_phys((void *)TEE_TEXT_VA_START);

	/* set secondary entry address and release core */
	write32(pa, src_base + SRC_GPR1 + 8);
	write32(pa, src_base + SRC_GPR1 + 16);
	write32(pa, src_base + SRC_GPR1 + 24);

	write32(BM_SRC_SCR_CPU_ENABLE_ALL, src_base + SRC_SCR);
}
#endif

/*
 * Platform CPU reset late function executed with MMU
 * OFF. The CSU must be initialized here to allow
 * access to Non-Secure Memory from Secure code without
 * aborting
 */
void plat_cpu_reset_late(void)
{
	if (get_core_pos() == 0) {
#if defined(CFG_BOOT_SYNC_CPU)
		psci_boot_allcpus();
#endif

#ifdef CFG_SCU
		scu_init();
#endif

#ifdef CFG_CSU
		csu_init();
#endif
	}
}
