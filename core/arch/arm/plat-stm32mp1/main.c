// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2018, STMicroelectronics
 * Copyright (c) 2016-2018, Linaro Limited
 */

#include <boot_api.h>
#include <console.h>
#include <drivers/gic.h>
#include <drivers/stm32_uart.h>
#include <kernel/generic_boot.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/pm_stubs.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <sm/psci.h>
#include <tee/entry_std.h>
#include <tee/entry_fast.h>

register_phys_mem(MEM_AREA_IO_NSEC, CONSOLE_UART_BASE, CONSOLE_UART_SIZE);

register_phys_mem(MEM_AREA_IO_SEC, GIC_BASE, GIC_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, BKP_REGS_BASE, SMALL_PAGE_SIZE);

static struct gic_data gic_data;
static struct console_pdata console_data;

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

void console_init(void)
{
	stm32_uart_init(&console_data, CONSOLE_UART_BASE);
	register_serial_console(&console_data.chip);
}

void main_init_gic(void)
{
	void *gicc_base;
	void *gicd_base;

	gicc_base = phys_to_virt(GIC_BASE + GICC_OFFSET, MEM_AREA_IO_SEC);
	gicd_base = phys_to_virt(GIC_BASE + GICD_OFFSET, MEM_AREA_IO_SEC);
	if (!gicc_base || !gicd_base)
		panic();

	gic_init(&gic_data, (vaddr_t)gicc_base, (vaddr_t)gicd_base);
	itr_init(&gic_data.chip);
}

void main_secondary_init_gic(void)
{
	gic_cpu_init(&gic_data);
}

/*
 * SMP boot support and access to the mailbox
 */
#define GIC_SEC_SGI_0		8

static vaddr_t bckreg_base(void)
{
	static void *va;

	if (!cpu_mmu_enabled())
		return BKP_REGS_BASE + BKP_REGISTER_OFF;

	if (!va)
		va = phys_to_virt(BKP_REGS_BASE + BKP_REGISTER_OFF,
				  MEM_AREA_IO_SEC);

	return (vaddr_t)va;
}

static uint32_t *bckreg_address(unsigned int idx)
{
	return (uint32_t *)bckreg_base() + idx;
}

static void release_secondary_early_hpen(size_t pos)
{
	uint32_t *p_entry = bckreg_address(BCKR_CORE1_BRANCH_ADDRESS);
	uint32_t *p_magic = bckreg_address(BCKR_CORE1_MAGIC_NUMBER);

	*p_entry = TEE_LOAD_ADDR;
	*p_magic = BOOT_API_A7_CORE1_MAGIC_NUMBER;

	dmb();
	isb();
	itr_raise_sgi(GIC_SEC_SGI_0, BIT(pos));
}

int psci_cpu_on(uint32_t core_id, uint32_t entry, uint32_t context_id)
{
	size_t pos = get_core_pos_mpidr(core_id);
	static bool core_is_released[CFG_TEE_CORE_NB_CORE];

	if (!pos || pos >= CFG_TEE_CORE_NB_CORE)
		return PSCI_RET_INVALID_PARAMETERS;

	DMSG("core pos: %zu: ns_entry %#" PRIx32, pos, entry);

	if (core_is_released[pos]) {
		DMSG("core %zu already released", pos);
		return PSCI_RET_DENIED;
	}
	core_is_released[pos] = true;

	generic_boot_set_core_ns_entry(pos, entry, context_id);
	release_secondary_early_hpen(pos);

	return PSCI_RET_SUCCESS;
}
