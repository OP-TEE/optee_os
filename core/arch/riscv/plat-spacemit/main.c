// SPDX-License-Identifier: BSD-2-Clause
/*
 * SpacemiT K1 platform
 */

#include <console.h>
#include <drivers/ns16550.h>
#include <kernel/boot.h>
#include <kernel/interrupt.h>
#include <platform_config.h>
#include <riscv.h>

#ifdef CFG_16550_UART
static struct ns16550_data console_data __nex_bss;
register_phys_mem_pgdir(MEM_AREA_IO_NSEC, UART0_BASE, CORE_MMU_PGDIR_SIZE);
#endif

register_ddr(DRAM0_BASE, DRAM0_SIZE);
register_ddr(DRAM1_BASE, DRAM1_SIZE);

#ifdef CFG_16550_UART
void plat_console_init(void)
{
	/* Polled output only: the UART (and its IER.UUE) stays set up by Linux/U-Boot */
	ns16550_init(&console_data, UART0_BASE, IO_WIDTH_U32, UART0_REG_SHIFT);
	register_serial_console(&console_data.chip);
}
#endif

/* No secure interrupt sources yet: mask external interrupts instead of panicking. */
void interrupt_main_handler(void)
{
	clear_csr(CSR_XIE, CSR_XIE_EIE);
}
