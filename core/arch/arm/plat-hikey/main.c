/*
 * Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <console.h>
#include <drivers/pl011.h>
#ifdef CFG_SPI
#include <drivers/pl022_spi.h>
#include <drivers/pl061_gpio.h>
#endif
#include <hikey_peripherals.h>
#include <initcall.h>
#include <io.h>
#include <kernel/generic_boot.h>
#include <kernel/panic.h>
#include <kernel/pm_stubs.h>
#include <mm/tee_pager.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>
#include <tee/entry_std.h>
#include <tee/entry_fast.h>

static void main_fiq(void);

static const struct thread_handlers handlers = {
	.std_smc = tee_entry_std,
	.fast_smc = tee_entry_fast,
	.nintr = main_fiq,
	.cpu_on = cpu_on_handler,
	.cpu_off = pm_do_nothing,
	.cpu_suspend = pm_do_nothing,
	.cpu_resume = pm_do_nothing,
	.system_off = pm_do_nothing,
	.system_reset = pm_do_nothing,
};

static struct pl011_data console_data;

register_phys_mem(MEM_AREA_IO_NSEC, CONSOLE_UART_BASE, PL011_REG_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, PMUSSI_BASE, PMUSSI_REG_SIZE);
#ifdef CFG_SPI
register_phys_mem(MEM_AREA_IO_NSEC, PERI_BASE, PERI_BASE_REG_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, PMX0_BASE, PMX0_REG_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, PMX1_BASE, PMX1_REG_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, GPIO6_BASE, PL061_REG_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, SPI_BASE, PL022_REG_SIZE);
#endif

const struct thread_handlers *generic_boot_get_handlers(void)
{
	return &handlers;
}

static void main_fiq(void)
{
	panic();
}

void console_init(void)
{
	pl011_init(&console_data, CONSOLE_UART_BASE, CONSOLE_UART_CLK_IN_HZ,
		   CONSOLE_BAUDRATE);
	register_serial_console(&console_data.chip);
}

vaddr_t nsec_periph_base(paddr_t pa)
{
	if (cpu_mmu_enabled())
		return (vaddr_t)phys_to_virt(pa, MEM_AREA_IO_NSEC);
	return (vaddr_t)pa;
}

#ifdef CFG_SPI
void spi_init(void)
{
	uint32_t shifted_val, read_val;
	vaddr_t peri_base = nsec_periph_base(PERI_BASE);
	vaddr_t pmx0_base = nsec_periph_base(PMX0_BASE);
	vaddr_t pmx1_base = nsec_periph_base(PMX1_BASE);

	DMSG("take SPI0 out of reset\n");
	shifted_val = PERI_RST3_SSP;
	/*
	 * no need to read PERI_SC_PERIPH_RSTDIS3 first
	 * as all the bits are processed and cleared after writing
	 */
	write32(shifted_val, peri_base + PERI_SC_PERIPH_RSTDIS3);
	DMSG("PERI_SC_PERIPH_RSTDIS3: 0x%x\n",
		read32(peri_base + PERI_SC_PERIPH_RSTDIS3));

	/*
	 * wait until the requested device is out of reset
	 * and ready to be used
	 */
	do {
		read_val = read32(peri_base + PERI_SC_PERIPH_RSTSTAT3);
	} while (read_val & shifted_val);
	DMSG("PERI_SC_PERIPH_RSTSTAT3: 0x%x\n", read_val);

	DMSG("enable SPI clock\n");
	/*
	 * no need to read PERI_SC_PERIPH_CLKEN3 first
	 * as all the bits are processed and cleared after writing
	 */
	shifted_val = PERI_CLK3_SSP;
	write32(shifted_val, peri_base + PERI_SC_PERIPH_CLKEN3);
	DMSG("PERI_SC_PERIPH_CLKEN3: 0x%x\n",
		read32(peri_base + PERI_SC_PERIPH_CLKEN3));

	DMSG("PERI_SC_PERIPH_CLKSTAT3: 0x%x\n",
		read32(peri_base + PERI_SC_PERIPH_CLKSTAT3));

	/*
	 * GPIO6_2 can be configured as PINMUX_GPIO, but as PINMUX_SPI, HW IP
	 * will control the chip select pin so we don't have to manually do it.
	 * The only concern is that the IP will pulse it between each packet,
	 * which might not work with certain clients. There seems to be no
	 * option to configure it to stay enabled for the total duration of the
	 * transfer.
	 * ref: http://infocenter.arm.com/help/topic/com.arm.doc.ddi0194h/CJACFAFG.html
	 */
	DMSG("configure gpio6 pins 0-3 as SPI\n");
	write32(PINMUX_SPI, pmx0_base + PMX0_IOMG104);
	write32(PINMUX_SPI, pmx0_base + PMX0_IOMG105);
	write32(PINMUX_SPI, pmx0_base + PMX0_IOMG106);
	write32(PINMUX_SPI, pmx0_base + PMX0_IOMG107);

	DMSG("configure gpio6 pins 0-3 as nopull\n");
	write32(PINCFG_NOPULL, pmx1_base + PMX1_IOCG104);
	write32(PINCFG_NOPULL, pmx1_base + PMX1_IOCG105);
	write32(PINCFG_NOPULL, pmx1_base + PMX1_IOCG106);
	write32(PINCFG_NOPULL, pmx1_base + PMX1_IOCG107);

#ifdef CFG_SPI_TEST
	spi_test();
#endif
}
#endif

static TEE_Result peripherals_init(void)
{
	vaddr_t pmussi_base = nsec_periph_base(PMUSSI_BASE);

	DMSG("enable LD021_1V8 source (pin 35) on LS connector\n");
	/*
	 * Mezzanine cards usually use this to source level shifters for
	 * UART, GPIO, SPI, I2C, etc so if not enabled, connected
	 * peripherals will not work either (during bootloader stage)
	 * until linux is booted.
	 */
	io_mask8(pmussi_base + PMUSSI_LDO21_REG_ADJ, PMUSSI_LDO21_REG_VL_1V8,
		PMUSSI_LDO21_REG_VL_MASK);
	write8(PMUSSI_ENA_LDO21, pmussi_base + PMUSSI_ENA_LDO17_22);

#ifdef CFG_SPI
	spi_init();
#endif
	return TEE_SUCCESS;
}

driver_init(peripherals_init);
