// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, Aspeed Technology Inc.
 */

#include <console.h>
#include <drivers/gic.h>
#include <drivers/serial8250_uart.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/panic.h>

enum TZM_PERM {
	TZM_PERM_VGA_CURSOR_RD,
	TZM_PERM_VGA_CRT_RD,
	TZM_PERM_SOC_DISPLAY_RD,
	TZM_PERM_PCIE_BUS1_RW,
	TZM_PERM_VIDEO_HIGH_WR,
	TZM_PERM_CPU_RW,
	TZM_PERM_SLI_RW,
	TZM_PERM_PCIE_BUS2_RW,
	TZM_PERM_USB20_HUB_EHCI1_DMA_RW,
	TZM_PERM_USB20_DEV_EHCI2_DMA_RW,
	TZM_PERM_USB11_UCHI_HOST_RW,
	TZM_PERM_AHB_RW,
	TZM_PERM_CM3_DATA_RW,
	TZM_PERM_CM3_INSN_RW,
	TZM_PERM_MAC0_DMA_RW,
	TZM_PERM_MAC1_DMA_RW,
	TZM_PERM_SDIO_DMA_RW,
	TZM_PERM_PILOT_RW,
	TZM_PERM_XDMA1_RW,
	TZM_PERM_MCTP1_RW,
	TZM_PERM_VIDEO_FLAG_RW,
	TZM_PERM_VIDEO_LOW_WR,
	TZM_PERM_2D_DATA_RW,
	TZM_PERM_ENCRYPT_RW,
	TZM_PERM_MCTP2_RW,
	TZM_PERM_XDMA2_RW,
	TZM_PERM_ECC_RSA_RW,
};

register_phys_mem(MEM_AREA_IO_NSEC, CONSOLE_UART_BASE, SMALL_PAGE_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, GIC_BASE + GICD_OFFSET, GIC_DIST_REG_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, GIC_BASE + GICC_OFFSET, GIC_CPU_REG_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, AHBC_BASE, SMALL_PAGE_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, SCU_BASE, SMALL_PAGE_SIZE);

#define AHBC_REG_WR_PROT	0x204
#define AHBC_TZP_ACCESS1	0x280
#define AHBC_TZP_HACE		BIT(20)
#define AHBC_TZM_ST(i)		(0x300 + ((i) * 0x10))
#define AHBC_TZM_ED(i)		(0x304 + ((i) * 0x10))
#define AHBC_TZM_PERM(i)	(0x308 + ((i) * 0x10))

register_ddr(CFG_DRAM_BASE, CFG_DRAM_SIZE);

static struct serial8250_uart_data console_data;
static struct gic_data gic_data;

void main_init_gic(void)
{
	gic_init(&gic_data, GIC_BASE + GICC_OFFSET, GIC_BASE + GICD_OFFSET);
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

void console_init(void)
{
	serial8250_uart_init(&console_data, CONSOLE_UART_BASE,
			     CONSOLE_UART_CLK_IN_HZ, CONSOLE_BAUDRATE);
	register_serial_console(&console_data.chip);
}

void plat_primary_init_early(void)
{
	vaddr_t ahbc_virt = 0;
	uint32_t tzm_perm = 0;

	ahbc_virt = core_mmu_get_va(AHBC_BASE,
				    MEM_AREA_IO_SEC, SMALL_PAGE_SIZE);
	if (!ahbc_virt)
		panic();

	tzm_perm = BIT(TZM_PERM_CPU_RW);
	if (IS_ENABLED(CFG_ASPEED_CRYPTO_DRIVER)) {
		tzm_perm |= BIT(TZM_PERM_ENCRYPT_RW);
		io_write32(ahbc_virt + AHBC_TZP_ACCESS1, AHBC_TZP_HACE);
	}

	io_write32(ahbc_virt + AHBC_TZM_PERM(0), tzm_perm);
	io_write32(ahbc_virt + AHBC_TZM_ED(0),
		   CFG_TZDRAM_START + CFG_TZDRAM_SIZE - 1);
	io_write32(ahbc_virt + AHBC_TZM_ST(0),
		   CFG_TZDRAM_START | BIT(0));
	io_write32(ahbc_virt + AHBC_REG_WR_PROT, BIT(16));
}
