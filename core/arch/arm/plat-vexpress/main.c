// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016-2020, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <arm.h>
#include <console.h>
#include <drivers/gic.h>
#include <drivers/pl011.h>
#include <drivers/tpm2_mmio.h>
#include <drivers/tpm2_ptp_fifo.h>
#include <drivers/tzc400.h>
#include <initcall.h>
#include <keep.h>
#include <kernel/boot.h>
#include <kernel/interrupt.h>
#include <kernel/misc.h>
#include <kernel/notif.h>
#include <kernel/panic.h>
#include <kernel/spinlock.h>
#include <kernel/tee_time.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <sm/psci.h>
#include <stdint.h>
#include <string.h>
#include <trace.h>

static struct gic_data gic_data __nex_bss;
static struct pl011_data console_data __nex_bss;

register_phys_mem_pgdir(MEM_AREA_IO_SEC, CONSOLE_UART_BASE, PL011_REG_SIZE);
#if defined(CFG_DRIVERS_TPM2_MMIO)
register_phys_mem_pgdir(MEM_AREA_IO_SEC, TPM2_BASE, TPM2_REG_SIZE);
#endif
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

#ifdef GIC_BASE

register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICD_BASE, GIC_DIST_REG_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICC_BASE, GIC_DIST_REG_SIZE);

void main_init_gic(void)
{
#if defined(CFG_WITH_ARM_TRUSTED_FW)
	/* On ARMv8, GIC configuration is initialized in ARM-TF */
	gic_init_base_addr(&gic_data, GIC_BASE + GICC_OFFSET,
			   GIC_BASE + GICD_OFFSET);
#else
	gic_init(&gic_data, GIC_BASE + GICC_OFFSET, GIC_BASE + GICD_OFFSET);
#endif
	itr_init(&gic_data.chip);
}

#if !defined(CFG_WITH_ARM_TRUSTED_FW)
void main_secondary_init_gic(void)
{
	gic_cpu_init(&gic_data);
}
#endif

#endif

void itr_core_handler(void)
{
	gic_it_handle(&gic_data);
}

void console_init(void)
{
	pl011_init(&console_data, CONSOLE_UART_BASE, CONSOLE_UART_CLK_IN_HZ,
		   CONSOLE_BAUDRATE);
	register_serial_console(&console_data.chip);
}

#if defined(IT_CONSOLE_UART) && !defined(CFG_VIRTUALIZATION) && \
	!(defined(CFG_WITH_ARM_TRUSTED_FW) && defined(CFG_ARM_GICV2))
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

	while (cons->ops->have_rx_data(cons)) {
		int ch __maybe_unused = cons->ops->getchar(cons);

		DMSG("got 0x%x", ch);
	}
}

static enum itr_return console_itr_cb(struct itr_handler *h __maybe_unused)
{
	if (notif_async_is_started()) {
		/*
		 * Asynchronous notifications are enabled, lets read from
		 * uart in the bottom half instead.
		 */
		itr_disable(IT_CONSOLE_UART);
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
		itr_enable(IT_CONSOLE_UART);
		break;
	case NOTIF_EVENT_STOPPED:
		DMSG("Asynchronous notifications stopped");
		itr_enable(IT_CONSOLE_UART);
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
	itr_add(&console_itr);
	itr_enable(IT_CONSOLE_UART);
	if (IS_ENABLED(CFG_CORE_ASYNC_NOTIF))
		notif_register_driver(&console_notif);
	return TEE_SUCCESS;
}
driver_init(init_console_itr);
#endif

#if defined(CFG_DRIVERS_TPM2_MMIO)
static TEE_Result init_tpm2(void)
{
	enum tpm2_result res = TPM2_OK;

	res = tpm2_mmio_init(TPM2_BASE);
	if (res) {
		EMSG("Failed to initialize TPM2 MMIO");
		return TEE_ERROR_GENERIC;
	}

	DMSG("TPM2 Chip initialized");

	return TEE_SUCCESS;
}
driver_init(init_tpm2);
#endif /* defined(CFG_DRIVERS_TPM2_MMIO) */

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
