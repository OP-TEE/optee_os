// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015, Linaro Limited
 */

#include <console.h>
#include <drivers/pl011.h>
#ifdef CFG_SPI
#include <drivers/pl022_spi.h>
#include <drivers/pl061_gpio.h>
#endif
#if defined(PLATFORM_FLAVOR_hikey)
#include <hikey_peripherals.h>
#endif
#include <initcall.h>
#include <io.h>
#include <kernel/panic.h>
#include <mm/tee_pager.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>

static struct pl011_data console_data __nex_bss;

register_phys_mem_pgdir(MEM_AREA_IO_NSEC, CONSOLE_UART_BASE, PL011_REG_SIZE);
#if defined(PLATFORM_FLAVOR_hikey)
register_phys_mem_pgdir(MEM_AREA_IO_NSEC, PMUSSI_BASE, PMUSSI_REG_SIZE);
#endif
#if defined(CFG_SPI) && defined(PLATFORM_FLAVOR_hikey)
register_phys_mem_pgdir(MEM_AREA_IO_NSEC, PERI_BASE, PERI_BASE_REG_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_NSEC, PMX0_BASE, PMX0_REG_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_NSEC, PMX1_BASE, PMX1_REG_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_NSEC, GPIO6_BASE, PL061_REG_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_NSEC, SPI_BASE, PL022_REG_SIZE);
#endif
register_ddr(DRAM0_BASE, DRAM0_SIZE_NSEC);
#ifdef DRAM1_SIZE_NSEC
register_ddr(DRAM1_BASE, DRAM1_SIZE_NSEC);
#endif
#ifdef DRAM2_SIZE_NSEC
register_ddr(DRAM2_BASE, DRAM2_SIZE_NSEC);
#endif

void plat_console_init(void)
{
	pl011_init(&console_data, CONSOLE_UART_BASE, CONSOLE_UART_CLK_IN_HZ,
		   CONSOLE_BAUDRATE);
	register_serial_console(&console_data.chip);
}

#if defined(PLATFORM_FLAVOR_hikey)
#ifdef CFG_SPI
void spi_init(void)
{
	uint32_t shifted_val, read_val;
	vaddr_t peri_base = core_mmu_get_va(PERI_BASE, MEM_AREA_IO_NSEC,
					    PERI_BASE_REG_SIZE);
	vaddr_t pmx0_base = core_mmu_get_va(PMX0_BASE, MEM_AREA_IO_NSEC,
					    PMX0_REG_SIZE);
	vaddr_t pmx1_base = core_mmu_get_va(PMX1_BASE, MEM_AREA_IO_NSEC,
					    PMX1_REG_SIZE);

	DMSG("take SPI0 out of reset");
	shifted_val = PERI_RST3_SSP;
	/*
	 * no need to read PERI_SC_PERIPH_RSTDIS3 first
	 * as all the bits are processed and cleared after writing
	 */
	io_write32(peri_base + PERI_SC_PERIPH_RSTDIS3, shifted_val);
	DMSG("PERI_SC_PERIPH_RSTDIS3: 0x%x",
		io_read32(peri_base + PERI_SC_PERIPH_RSTDIS3));

	/*
	 * wait until the requested device is out of reset
	 * and ready to be used
	 */
	do {
		read_val = io_read32(peri_base + PERI_SC_PERIPH_RSTSTAT3);
	} while (read_val & shifted_val);
	DMSG("PERI_SC_PERIPH_RSTSTAT3: 0x%x", read_val);

	DMSG("enable SPI clock");
	/*
	 * no need to read PERI_SC_PERIPH_CLKEN3 first
	 * as all the bits are processed and cleared after writing
	 */
	shifted_val = PERI_CLK3_SSP;
	io_write32(peri_base + PERI_SC_PERIPH_CLKEN3, shifted_val);
	DMSG("PERI_SC_PERIPH_CLKEN3: 0x%x",
		io_read32(peri_base + PERI_SC_PERIPH_CLKEN3));

	DMSG("PERI_SC_PERIPH_CLKSTAT3: 0x%x",
		io_read32(peri_base + PERI_SC_PERIPH_CLKSTAT3));

	/*
	 * GPIO6_2 can be configured as PINMUX_GPIO, but as PINMUX_SPI, HW IP
	 * will control the chip select pin so we don't have to manually do it.
	 * The only concern is that the IP will pulse it between each packet,
	 * which might not work with certain clients. There seems to be no
	 * option to configure it to stay enabled for the total duration of the
	 * transfer.
	 * ref: http://infocenter.arm.com/help/topic/com.arm.doc.ddi0194h/CJACFAFG.html
	 */
	DMSG("configure gpio6 pins 0-3 as SPI");
	io_write32(pmx0_base + PMX0_IOMG104, PINMUX_SPI);
	io_write32(pmx0_base + PMX0_IOMG105, PINMUX_SPI);
	io_write32(pmx0_base + PMX0_IOMG106, PINMUX_SPI);
	io_write32(pmx0_base + PMX0_IOMG107, PINMUX_SPI);

	DMSG("configure gpio6 pins 0-3 as nopull");
	io_write32(pmx1_base + PMX1_IOCG104, PINCFG_NOPULL);
	io_write32(pmx1_base + PMX1_IOCG105, PINCFG_NOPULL);
	io_write32(pmx1_base + PMX1_IOCG106, PINCFG_NOPULL);
	io_write32(pmx1_base + PMX1_IOCG107, PINCFG_NOPULL);

#ifdef CFG_SPI_TEST
	spi_test();
#endif
}
#endif

static TEE_Result peripherals_init(void)
{
	vaddr_t pmussi_base = core_mmu_get_va(PMUSSI_BASE, MEM_AREA_IO_NSEC,
					      PMUSSI_REG_SIZE);

	DMSG("enable LD021_1V8 source (pin 35) on LS connector");
	/*
	 * Mezzanine cards usually use this to source level shifters for
	 * UART, GPIO, SPI, I2C, etc so if not enabled, connected
	 * peripherals will not work either (during bootloader stage)
	 * until linux is booted.
	 */
	io_mask8(pmussi_base + PMUSSI_LDO21_REG_ADJ, PMUSSI_LDO21_REG_VL_1V8,
		 PMUSSI_LDO21_REG_VL_MASK);
	io_write8(pmussi_base + PMUSSI_ENA_LDO17_22, PMUSSI_ENA_LDO21);

#ifdef CFG_SPI
	spi_init();
#endif
	return TEE_SUCCESS;
}

driver_init(peripherals_init);
#endif /* PLATFORM_FLAVOR_hikey */
