// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Ahmed Fardi
 *
 * SpacemiT K1 and K3 platform
 */

#include <console.h>
#include <drivers/ns16550.h>
#include <kernel/boot.h>
#include <mm/core_memprot.h>
#include <platform_config.h>

#ifdef CFG_16550_UART
static struct ns16550_data console_data __nex_bss;
register_phys_mem_pgdir(MEM_AREA_IO_NSEC, UART0_BASE, CORE_MMU_PGDIR_SIZE);
#endif

register_ddr(DRAM0_BASE, DRAM0_SIZE);
#ifdef DRAM1_BASE
register_ddr(DRAM1_BASE, DRAM1_SIZE);
#endif

#ifdef CFG_16550_UART
void plat_console_init(void)
{
	/* Polled output only: Linux and U-Boot keep the UART set up */
	ns16550_init(&console_data, UART0_BASE, IO_WIDTH_U32, UART0_REG_SHIFT);
	register_serial_console(&console_data.chip);
}
#endif
