// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014-2016, STMicroelectronics International N.V.
 */

#include <arm32.h>
#include <console.h>
#include <drivers/gic.h>
#include <drivers/stih_asc.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/interrupt.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/tz_ssvce_pl310.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <stdint.h>
#include <tee/entry_fast.h>
#include <tee/entry_std.h>
#include <trace.h>
#include <util.h>

register_phys_mem_pgdir(MEM_AREA_IO_SEC, CPU_IOMEM_BASE, CPU_IOMEM_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, RNG_BASE, RNG_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_NSEC, UART_CONSOLE_BASE, STIH_ASC_REG_SIZE);

#ifdef DRAM0_BASE
register_ddr(DRAM0_BASE, DRAM0_SIZE);
#endif
#ifdef DRAM1_BASE
register_ddr(DRAM1_BASE, DRAM1_SIZE);
#endif

static struct gic_data gic_data;
static struct stih_asc_pd console_data;

#if defined(PLATFORM_FLAVOR_b2260)
static bool ns_resources_ready(void)
{
	return true;
}
#else
/* some nonsecure resource might not be ready (uart) */
static int boot_is_completed;
static bool ns_resources_ready(void)
{
	return !!boot_is_completed;
}

/* Overriding the default __weak tee_entry_std() */
uint32_t tee_entry_std(struct optee_msg_arg *arg, uint32_t num_params)
{
	boot_is_completed = 1;

	return __tee_entry_std(arg, num_params);
}
#endif

void console_init(void)
{
	stih_asc_init(&console_data, UART_CONSOLE_BASE);
}

void console_putc(int ch)
{

	if (ns_resources_ready()) {
		struct serial_chip *cons = &console_data.chip;

		if (ch == '\n')
			cons->ops->putc(cons, '\r');
		cons->ops->putc(cons, ch);
	}
}

void console_flush(void)
{
	if (ns_resources_ready()) {
		struct serial_chip *cons = &console_data.chip;

		cons->ops->flush(cons);
	}
}

vaddr_t pl310_base(void)
{
	static void *va;

	if (cpu_mmu_enabled()) {
		if (!va)
			va = phys_to_virt(PL310_BASE, MEM_AREA_IO_SEC, 1);
		return (vaddr_t)va;
	}
	return PL310_BASE;
}

void arm_cl2_config(vaddr_t pl310)
{
	/* pl310 off */
	io_write32(pl310 + PL310_CTRL, 0);

	/* config PL310 */
	io_write32(pl310 + PL310_TAG_RAM_CTRL, PL310_TAG_RAM_CTRL_INIT);
	io_write32(pl310 + PL310_DATA_RAM_CTRL, PL310_DATA_RAM_CTRL_INIT);
	io_write32(pl310 + PL310_AUX_CTRL, PL310_AUX_CTRL_INIT);
	io_write32(pl310 + PL310_PREFETCH_CTRL, PL310_PREFETCH_CTRL_INIT);
	io_write32(pl310 + PL310_POWER_CTRL, PL310_POWER_CTRL_INIT);

	/* invalidate all pl310 cache ways */
	arm_cl2_invbyway(pl310);
}

void plat_primary_init_early(void)
{
	int i;

	assert(!cpu_mmu_enabled());

	io_write32(SCU_BASE + SCU_SAC, SCU_SAC_INIT);
	io_write32(SCU_BASE + SCU_NSAC, SCU_NSAC_INIT);
	io_write32(SCU_BASE + SCU_FILT_EA, CPU_PORT_FILT_END);
	io_write32(SCU_BASE + SCU_FILT_SA, CPU_PORT_FILT_START);
	io_write32(SCU_BASE + SCU_CTRL, SCU_CTRL_INIT);

	io_write32(pl310_base() + PL310_ADDR_FILT_END, CPU_PORT_FILT_END);
	io_write32(pl310_base() + PL310_ADDR_FILT_START,
		CPU_PORT_FILT_START | PL310_CTRL_ENABLE_BIT);

	/* TODO: gic_init scan fails, pre-init all SPIs are nonsecure */
	for (i = 0; i < (31 * 4); i += 4)
		io_write32(GIC_DIST_BASE + GIC_DIST_ISR1 + i, 0xFFFFFFFF);
}

void main_init_gic(void)
{
	vaddr_t gicc_base;
	vaddr_t gicd_base;

	gicc_base = (vaddr_t)phys_to_virt(GIC_CPU_BASE, MEM_AREA_IO_SEC, 1);
	gicd_base = (vaddr_t)phys_to_virt(GIC_DIST_BASE, MEM_AREA_IO_SEC, 1);

	if (!gicc_base || !gicd_base)
		panic();

	gic_init(&gic_data, gicc_base, gicd_base);
	itr_init(&gic_data.chip);
}

void main_secondary_init_gic(void)
{
	gic_cpu_init(&gic_data);
}

void itr_core_handler(void)
{
	gic_it_handle(&gic_data);
}
