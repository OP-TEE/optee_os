// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016-2023, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <arm.h>
#include <config.h>
#include <console.h>
#include <drivers/gic.h>
#include <drivers/hfic.h>
#include <drivers/pl011.h>
#include <drivers/tzc400.h>
#include <initcall.h>
#include <keep.h>
#include <kernel/boot.h>
#include <kernel/interrupt.h>
#include <kernel/misc.h>
#include <kernel/notif.h>
#include <kernel/panic.h>
#include <kernel/thread_spmc.h>
#include <kernel/timer.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <sm/psci.h>
#include <stdint.h>
#include <trace.h>

static struct pl011_data console_data __nex_bss;

register_phys_mem_pgdir(MEM_AREA_IO_SEC, CONSOLE_UART_BASE, PL011_REG_SIZE);
#if defined(PLATFORM_FLAVOR_fvp)
register_phys_mem(MEM_AREA_RAM_SEC, TZCDRAM_BASE, TZCDRAM_SIZE);
#endif
#if defined(PLATFORM_FLAVOR_qemu_virt)
register_phys_mem_pgdir(MEM_AREA_IO_SEC, SECRAM_BASE, SECRAM_COHERENT_SIZE);
#endif
#ifdef DRAM0_BASE
register_ddr(DRAM0_BASE, DRAM0_SIZE);
#endif
#ifdef DRAM1_BASE
register_ddr(DRAM1_BASE, DRAM1_SIZE);
#endif

#ifdef CFG_GIC
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICC_BASE, GIC_CPU_REG_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICD_BASE, GIC_DIST_REG_SIZE);
#ifdef GIC_REDIST_BASE
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GIC_REDIST_BASE, GIC_REDIST_SIZE);
#endif

void boot_primary_init_intc(void)
{
#ifdef GIC_REDIST_BASE
	gic_init_v3(GIC_BASE + GICC_OFFSET, GIC_BASE + GICD_OFFSET,
		    GIC_REDIST_BASE);
#else
	gic_init(GIC_BASE + GICC_OFFSET, GIC_BASE + GICD_OFFSET);
#endif
	if (IS_ENABLED(CFG_CORE_SEL1_SPMC) &&
	    IS_ENABLED(CFG_CORE_ASYNC_NOTIF)) {
		size_t it = CFG_CORE_ASYNC_NOTIF_GIC_INTID;

		if (it >= GIC_SGI_SEC_BASE && it <= GIC_SGI_SEC_MAX)
			gic_init_donate_sgi_to_ns(it);
		thread_spmc_set_async_notif_intid(it);
	}
}

void boot_secondary_init_intc(void)
{
	gic_init_per_cpu();
}
#endif /*CFG_GIC*/

#ifdef CFG_CORE_HAFNIUM_INTC
void boot_primary_init_intc(void)
{
	hfic_init();
}
#endif

void plat_console_init(void)
{
	pl011_init(&console_data, CONSOLE_UART_BASE, CONSOLE_UART_CLK_IN_HZ,
		   CONSOLE_BAUDRATE);
	register_serial_console(&console_data.chip);
}

#if (defined(CFG_GIC) || defined(CFG_CORE_HAFNIUM_INTC)) && \
	defined(IT_CONSOLE_UART) && \
	!defined(CFG_NS_VIRTUALIZATION) && \
	!(defined(CFG_WITH_ARM_TRUSTED_FW) && defined(CFG_ARM_GICV2)) && \
	!defined(CFG_SEMIHOSTING_CONSOLE) && \
	!defined(CFG_FFA_CONSOLE)
/*
 * This cannot be enabled with TF-A and GICv3 because TF-A then need to
 * assign the interrupt number of the UART to OP-TEE (S-EL1). Currently
 * there's no way of TF-A to know which interrupts that OP-TEE will serve.
 * If TF-A doesn't assign the interrupt we're enabling below to OP-TEE it
 * will hang in EL3 since the interrupt will just be delivered again and
 * again.
 */

static void read_console(void)
{
	struct serial_chip *cons = &console_data.chip;

	if (!cons->ops->getchar || !cons->ops->have_rx_data)
		return;

	while (cons->ops->have_rx_data(cons)) {
		int ch __maybe_unused = cons->ops->getchar(cons);

		DMSG("got 0x%x", ch);
	}
}

static enum itr_return console_itr_cb(struct itr_handler *hdl __unused)
{
	if (notif_async_is_started()) {
		/*
		 * Asynchronous notifications are enabled, lets read from
		 * uart in the bottom half instead.
		 */
		console_data.chip.ops->rx_intr_disable(&console_data.chip);
		notif_send_async(NOTIF_VALUE_DO_BOTTOM_HALF);
	} else {
		read_console();
	}
	return ITRR_HANDLED;
}

static struct itr_handler console_itr = {
	.it = IT_CONSOLE_UART,
	.flags = ITRF_TRIGGER_LEVEL,
	.handler = console_itr_cb,
};
DECLARE_KEEP_PAGER(console_itr);

static void atomic_console_notif(struct notif_driver *ndrv __unused,
				 enum notif_event ev __maybe_unused)
{
	DMSG("Asynchronous notifications started, event %d", (int)ev);
}
DECLARE_KEEP_PAGER(atomic_console_notif);

static void yielding_console_notif(struct notif_driver *ndrv __unused,
				   enum notif_event ev)
{
	switch (ev) {
	case NOTIF_EVENT_DO_BOTTOM_HALF:
		read_console();
		console_data.chip.ops->rx_intr_enable(&console_data.chip);
		break;
	case NOTIF_EVENT_STOPPED:
		DMSG("Asynchronous notifications stopped");
		console_data.chip.ops->rx_intr_enable(&console_data.chip);
		break;
	default:
		EMSG("Unknown event %d", (int)ev);
	}
}

struct notif_driver console_notif = {
	.atomic_cb = atomic_console_notif,
	.yielding_cb = yielding_console_notif,
};

static TEE_Result init_console_itr(void)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	bool have_itr_ctrl = console_data.chip.ops->rx_intr_enable &&
			     console_data.chip.ops->rx_intr_disable;

	res = interrupt_add_handler_with_chip(interrupt_get_main_chip(),
					      &console_itr);
	if (res)
		return res;

	interrupt_enable(console_itr.chip, console_itr.it);

	if (IS_ENABLED(CFG_CORE_ASYNC_NOTIF) && have_itr_ctrl)
		notif_register_driver(&console_notif);
	return TEE_SUCCESS;
}
driver_init(init_console_itr);
#endif

#ifdef CFG_TZC400
register_phys_mem_pgdir(MEM_AREA_IO_SEC, TZC400_BASE, TZC400_REG_SIZE);

static TEE_Result init_tzc400(void)
{
	void *va;

	DMSG("Initializing TZC400");

	va = phys_to_virt(TZC400_BASE, MEM_AREA_IO_SEC, TZC400_REG_SIZE);
	if (!va) {
		EMSG("TZC400 not mapped");
		panic();
	}

	tzc_init((vaddr_t)va);
	tzc_dump_state();

	return TEE_SUCCESS;
}

service_init(init_tzc400);
#endif /*CFG_TZC400*/

#if defined(PLATFORM_FLAVOR_qemu_virt)
static void release_secondary_early_hpen(size_t pos)
{
	struct mailbox {
		uint64_t ep;
		uint64_t hpen[];
	} *mailbox;

	if (cpu_mmu_enabled())
		mailbox = phys_to_virt(SECRAM_BASE, MEM_AREA_IO_SEC,
				       SECRAM_COHERENT_SIZE);
	else
		mailbox = (void *)SECRAM_BASE;

	if (!mailbox)
		panic();

	mailbox->ep = TEE_LOAD_ADDR;
	dsb_ishst();
	mailbox->hpen[pos] = 1;
	dsb_ishst();
	sev();
}

int psci_cpu_on(uint32_t core_id, uint32_t entry, uint32_t context_id)
{
	size_t pos = get_core_pos_mpidr(core_id);
	static bool core_is_released[CFG_TEE_CORE_NB_CORE];

	if (!pos || pos >= CFG_TEE_CORE_NB_CORE)
		return PSCI_RET_INVALID_PARAMETERS;

	DMSG("core pos: %zu: ns_entry %#" PRIx32, pos, entry);

	if (core_is_released[pos]) {
		EMSG("core %zu already released", pos);
		return PSCI_RET_DENIED;
	}
	core_is_released[pos] = true;

	boot_set_core_ns_entry(pos, entry, context_id);
	release_secondary_early_hpen(pos);

	return PSCI_RET_SUCCESS;
}
#endif /*PLATFORM_FLAVOR_qemu_virt*/

#if defined(CFG_CALLOUT) && defined(IT_SEC_PHY_TIMER) && \
	!defined(CFG_CORE_SEL2_SPMC)
static TEE_Result init_callout_service(void)
{
	timer_init_callout_service(interrupt_get_main_chip(), IT_SEC_PHY_TIMER);

	return TEE_SUCCESS;
}

nex_early_init(init_callout_service);
#endif
