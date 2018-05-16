// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014-2016, STMicroelectronics International N.V.
 */

#include <arm32.h>
#include <console.h>
#include <drivers/gic.h>
#include <drivers/stih_asc.h>
#include <io.h>
#include <kernel/generic_boot.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/pm_stubs.h>
#include <kernel/tz_ssvce_pl310.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>
#include <tee/entry_std.h>
#include <tee/entry_fast.h>
#include <trace.h>
#include <util.h>

register_phys_mem(MEM_AREA_IO_SEC, CPU_IOMEM_BASE, CPU_IOMEM_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, RNG_BASE, RNG_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, UART_CONSOLE_BASE, STIH_ASC_REG_SIZE);

#ifdef DRAM0_BASE
register_ddr(DRAM0_BASE, DRAM0_SIZE);
#endif
#ifdef DRAM1_BASE
register_ddr(DRAM1_BASE, DRAM1_SIZE);
#endif

static struct gic_data gic_data;
static struct stih_asc_pd console_data;

static void main_fiq(void);

#if defined(PLATFORM_FLAVOR_b2260)
#define stm_tee_entry_std	tee_entry_std
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
static void stm_tee_entry_std(struct thread_smc_args *smc_args)
{
	boot_is_completed = 1;
	tee_entry_std(smc_args);
}
#endif

static const struct thread_handlers handlers = {
	.std_smc = stm_tee_entry_std,
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
			va = phys_to_virt(PL310_BASE, MEM_AREA_IO_SEC);
		return (vaddr_t)va;
	}
	return PL310_BASE;
}

void arm_cl2_config(vaddr_t pl310)
{
	/* pl310 off */
	write32(0, pl310 + PL310_CTRL);

	/* config PL310 */
	write32(PL310_TAG_RAM_CTRL_INIT, pl310 + PL310_TAG_RAM_CTRL);
	write32(PL310_DATA_RAM_CTRL_INIT, pl310 + PL310_DATA_RAM_CTRL);
	write32(PL310_AUX_CTRL_INIT, pl310 + PL310_AUX_CTRL);
	write32(PL310_PREFETCH_CTRL_INIT, pl310 + PL310_PREFETCH_CTRL);
	write32(PL310_POWER_CTRL_INIT, pl310 + PL310_POWER_CTRL);

	/* invalidate all pl310 cache ways */
	arm_cl2_invbyway(pl310);
}

void plat_cpu_reset_late(void)
{
	int i;

	assert(!cpu_mmu_enabled());

	/* Allow NSec to Imprecise abort */
	write_scr(SCR_AW);

	if (get_core_pos())
		return;

	write32(SCU_SAC_INIT, SCU_BASE + SCU_SAC);
	write32(SCU_NSAC_INIT, SCU_BASE + SCU_NSAC);
	write32(CPU_PORT_FILT_END, SCU_BASE + SCU_FILT_EA);
	write32(CPU_PORT_FILT_START, SCU_BASE + SCU_FILT_SA);
	write32(SCU_CTRL_INIT, SCU_BASE + SCU_CTRL);

	write32(CPU_PORT_FILT_END, pl310_base() + PL310_ADDR_FILT_END);
	write32(CPU_PORT_FILT_START | PL310_CTRL_ENABLE_BIT,
				   pl310_base() + PL310_ADDR_FILT_START);

	/* TODO: gic_init scan fails, pre-init all SPIs are nonsecure */
	for (i = 0; i < (31 * 4); i += 4)
		write32(0xFFFFFFFF, GIC_DIST_BASE + GIC_DIST_ISR1 + i);
}

void main_init_gic(void)
{
	vaddr_t gicc_base;
	vaddr_t gicd_base;

	gicc_base = (vaddr_t)phys_to_virt(GIC_CPU_BASE, MEM_AREA_IO_SEC);
	gicd_base = (vaddr_t)phys_to_virt(GIC_DIST_BASE, MEM_AREA_IO_SEC);

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
