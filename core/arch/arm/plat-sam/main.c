// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2017 Timesys Corporation.
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

#include <arm32.h>
#include <console.h>
#include <drivers/atmel_uart.h>
#include <io.h>
#include <kernel/generic_boot.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/pm_stubs.h>
#include <kernel/tz_ssvce_def.h>
#include <kernel/tz_ssvce_pl310.h>
#include <matrix.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <sama5d2.h>
#include <stdint.h>
#include <sm/optee_smc.h>
#include <tee/entry_fast.h>
#include <tee/entry_std.h>
#include <tz_matrix.h>

static void main_fiq(void)
{
	panic();
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

static struct atmel_uart_data console_data;
register_phys_mem_pgdir(MEM_AREA_IO_SEC, CONSOLE_UART_BASE,
			CORE_MMU_PGDIR_SIZE);

void console_init(void)
{
	atmel_uart_init(&console_data, CONSOLE_UART_BASE);
	register_serial_console(&console_data.chip);
}

register_phys_mem_pgdir(MEM_AREA_IO_SEC, PL310_BASE, CORE_MMU_PGDIR_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, SFR_BASE, CORE_MMU_PGDIR_SIZE);

static vaddr_t sfr_base(void)
{
	static void *va;

	if (cpu_mmu_enabled()) {
		if (!va)
			va = phys_to_virt(SFR_BASE, MEM_AREA_IO_SEC);
		return (vaddr_t)va;
	}
	return SFR_BASE;
}

enum ram_config {RAMC_SRAM = 0, RAMC_L2CC};

static void l2_sram_config(enum ram_config setting)
{
	if (setting == RAMC_L2CC)
		io_write32(sfr_base() + SFR_L2CC_HRAMC, 0x1);
	else
		io_write32(sfr_base() + SFR_L2CC_HRAMC, 0x0);
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

void arm_cl2_config(vaddr_t pl310_base)
{
	io_write32(pl310_base + PL310_CTRL, 0);
	l2_sram_config(RAMC_L2CC);
	io_write32(pl310_base + PL310_AUX_CTRL, PL310_AUX_CTRL_INIT);
	io_write32(pl310_base + PL310_PREFETCH_CTRL, PL310_PREFETCH_CTRL_INIT);
	io_write32(pl310_base + PL310_POWER_CTRL, PL310_POWER_CTRL_INIT);

	/* invalidate all cache ways */
	arm_cl2_invbyway(pl310_base);
}

void arm_cl2_enable(vaddr_t pl310_base)
{
	/* Enable PL310 ctrl -> only set lsb bit */
	io_write32(pl310_base + PL310_CTRL, 1);
}

register_phys_mem_pgdir(MEM_AREA_IO_SEC, AT91C_BASE_MATRIX32,
			CORE_MMU_PGDIR_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, AT91C_BASE_MATRIX64,
			CORE_MMU_PGDIR_SIZE);

vaddr_t matrix32_base(void)
{
	static void *va;

	if (cpu_mmu_enabled()) {
		if (!va)
			va = phys_to_virt(AT91C_BASE_MATRIX32, MEM_AREA_IO_SEC);
		return (vaddr_t)va;
	}
	return AT91C_BASE_MATRIX32;
}

vaddr_t matrix64_base(void)
{
	static void *va;

	if (cpu_mmu_enabled()) {
		if (!va)
			va = phys_to_virt(AT91C_BASE_MATRIX64, MEM_AREA_IO_SEC);
		return (vaddr_t)va;
	}
	return AT91C_BASE_MATRIX64;
}

static void matrix_configure_slave_h64mx(void)
{
	unsigned int ddr_port;
	unsigned int ssr_setting;
	unsigned int sasplit_setting;
	unsigned int srtop_setting;

	/*
	 * 0: Bridge from H64MX to AXIMX
	 * (Internal ROM, Crypto Library, PKCC RAM): Always Secured
	 */

	/* 1: H64MX Peripheral Bridge: SDMMC0, SDMMC1 Non-Secure */
	srtop_setting =	MATRIX_SRTOP(1, MATRIX_SRTOP_VALUE_128M)
			| MATRIX_SRTOP(2, MATRIX_SRTOP_VALUE_128M);
	sasplit_setting = MATRIX_SASPLIT(1, MATRIX_SASPLIT_VALUE_128M)
			| MATRIX_SASPLIT(2, MATRIX_SASPLIT_VALUE_128M);
	ssr_setting = (MATRIX_LANSECH_NS(1)
			| MATRIX_LANSECH_NS(2)
			| MATRIX_RDNSECH_NS(1)
			| MATRIX_RDNSECH_NS(2)
			| MATRIX_WRNSECH_NS(1)
			| MATRIX_WRNSECH_NS(2));
	matrix_configure_slave_security(matrix64_base(),
					H64MX_SLAVE_PERI_BRIDGE,
					srtop_setting,
					sasplit_setting,
					ssr_setting);

	/* 2 ~ 9 DDR2 Port1 ~ 7: Non-Secure, except op-tee tee/ta memory */
	srtop_setting = MATRIX_SRTOP(0, MATRIX_SRTOP_VALUE_128M);
	sasplit_setting = (MATRIX_SASPLIT(0, MATRIX_SASPLIT_VALUE_128M)
				| MATRIX_SASPLIT(1, MATRIX_SASPLIT_VALUE_128M)
				| MATRIX_SASPLIT(2, MATRIX_SASPLIT_VALUE_8M)
				| MATRIX_SASPLIT(3, MATRIX_SASPLIT_VALUE_128M));
	ssr_setting = (MATRIX_LANSECH_NS(0)
			| MATRIX_LANSECH_NS(1)
			| MATRIX_LANSECH_S(2)
			| MATRIX_LANSECH_NS(3)
			| MATRIX_RDNSECH_NS(0)
			| MATRIX_RDNSECH_NS(1)
			| MATRIX_RDNSECH_S(2)
			| MATRIX_RDNSECH_NS(3)
			| MATRIX_WRNSECH_NS(0)
			| MATRIX_WRNSECH_NS(1)
			| MATRIX_WRNSECH_S(2)
			| MATRIX_WRNSECH_NS(3));
	/* DDR port 0 not used from NWd */
	for (ddr_port = 1; ddr_port < 8; ddr_port++) {
		matrix_configure_slave_security(matrix64_base(),
					(H64MX_SLAVE_DDR2_PORT_0 + ddr_port),
					srtop_setting,
					sasplit_setting,
					ssr_setting);
	}

	/* 10: Internal SRAM 128K: Non-Secure */
	srtop_setting = MATRIX_SRTOP(0, MATRIX_SRTOP_VALUE_128K);
	sasplit_setting = MATRIX_SASPLIT(0, MATRIX_SASPLIT_VALUE_128K);
	ssr_setting = (MATRIX_LANSECH_NS(0)
			| MATRIX_RDNSECH_NS(0)
			| MATRIX_WRNSECH_NS(0));
	matrix_configure_slave_security(matrix64_base(),
					H64MX_SLAVE_INTERNAL_SRAM,
					srtop_setting,
					sasplit_setting,
					ssr_setting);

	/* 11:  Internal SRAM 128K (Cache L2): Default */
	/* 12:  QSPI0: Default */
	/* 13:  QSPI1: Default */
	/* 14:  AESB: Default */
}

static void matrix_configure_slave_h32mx(void)
{
	unsigned int ssr_setting;
	unsigned int sasplit_setting;
	unsigned int srtop_setting;

	/* 0: Bridge from H32MX to H64MX: Not Secured */
	/* 1: H32MX Peripheral Bridge 0: Not Secured */
	/* 2: H32MX Peripheral Bridge 1: Not Secured */

	/*
	 * 3: External Bus Interface
	 * EBI CS0 Memory(256M) ----> Slave Region 0, 1
	 * EBI CS1 Memory(256M) ----> Slave Region 2, 3
	 * EBI CS2 Memory(256M) ----> Slave Region 4, 5
	 * EBI CS3 Memory(128M) ----> Slave Region 6
	 * NFC Command Registers(128M) -->Slave Region 7
	 * NANDFlash(EBI CS3) --> Slave Region 6: Non-Secure
	 */
	srtop_setting =	MATRIX_SRTOP(6, MATRIX_SRTOP_VALUE_128M);
	srtop_setting |= MATRIX_SRTOP(7, MATRIX_SRTOP_VALUE_128M);
	sasplit_setting = MATRIX_SASPLIT(6, MATRIX_SASPLIT_VALUE_128M);
	sasplit_setting |= MATRIX_SASPLIT(7, MATRIX_SASPLIT_VALUE_128M);
	ssr_setting = (MATRIX_LANSECH_NS(6)
			| MATRIX_RDNSECH_NS(6)
			| MATRIX_WRNSECH_NS(6));
	ssr_setting |= (MATRIX_LANSECH_NS(7)
			| MATRIX_RDNSECH_NS(7)
			| MATRIX_WRNSECH_NS(7));
	matrix_configure_slave_security(matrix32_base(),
					H32MX_EXTERNAL_EBI,
					srtop_setting,
					sasplit_setting,
					ssr_setting);

	/* 4: NFC SRAM (4K): Non-Secure */
	srtop_setting = MATRIX_SRTOP(0, MATRIX_SRTOP_VALUE_8K);
	sasplit_setting = MATRIX_SASPLIT(0, MATRIX_SASPLIT_VALUE_8K);
	ssr_setting = (MATRIX_LANSECH_NS(0)
			| MATRIX_RDNSECH_NS(0)
			| MATRIX_WRNSECH_NS(0));
	matrix_configure_slave_security(matrix32_base(),
					H32MX_NFC_SRAM,
					srtop_setting,
					sasplit_setting,
					ssr_setting);

	/* 5:
	 * USB Device High Speed Dual Port RAM (DPR): 1M
	 * USB Host OHCI registers: 1M
	 * USB Host EHCI registers: 1M
	 */
	srtop_setting = (MATRIX_SRTOP(0, MATRIX_SRTOP_VALUE_1M)
			| MATRIX_SRTOP(1, MATRIX_SRTOP_VALUE_1M)
			| MATRIX_SRTOP(2, MATRIX_SRTOP_VALUE_1M));
	sasplit_setting = (MATRIX_SASPLIT(0, MATRIX_SASPLIT_VALUE_1M)
			| MATRIX_SASPLIT(1, MATRIX_SASPLIT_VALUE_1M)
			| MATRIX_SASPLIT(2, MATRIX_SASPLIT_VALUE_1M));
	ssr_setting = (MATRIX_LANSECH_NS(0)
			| MATRIX_LANSECH_NS(1)
			| MATRIX_LANSECH_NS(2)
			| MATRIX_RDNSECH_NS(0)
			| MATRIX_RDNSECH_NS(1)
			| MATRIX_RDNSECH_NS(2)
			| MATRIX_WRNSECH_NS(0)
			| MATRIX_WRNSECH_NS(1)
			| MATRIX_WRNSECH_NS(2));
	matrix_configure_slave_security(matrix32_base(),
					H32MX_USB,
					srtop_setting,
					sasplit_setting,
					ssr_setting);
}

static unsigned int security_ps_peri_id[] = {
	AT91C_ID_1,
	AT91C_ID_ARM,
	AT91C_ID_PIT,
	AT91C_ID_WDT,
	AT91C_ID_GMAC,
	AT91C_ID_XDMAC0,
	AT91C_ID_XDMAC1,
	AT91C_ID_ICM,
	AT91C_ID_AES,
	AT91C_ID_AESB,
	AT91C_ID_TDES,
	AT91C_ID_SHA,
	AT91C_ID_MPDDRC,
	AT91C_ID_HSMC,
	AT91C_ID_FLEXCOM0,
	AT91C_ID_FLEXCOM1,
	AT91C_ID_FLEXCOM2,
	AT91C_ID_FLEXCOM3,
	AT91C_ID_FLEXCOM4,
	AT91C_ID_UART0,
	AT91C_ID_UART1,
	AT91C_ID_UART2,
	AT91C_ID_UART3,
	AT91C_ID_UART4,
	AT91C_ID_TWI0,
	AT91C_ID_TWI1,
	AT91C_ID_SDMMC0,
	AT91C_ID_SDMMC1,
	AT91C_ID_SPI0,
	AT91C_ID_SPI1,
	AT91C_ID_TC0,
	AT91C_ID_TC1,
	AT91C_ID_PWM,
	AT91C_ID_ADC,
	AT91C_ID_UHPHS,
	AT91C_ID_UDPHS,
	AT91C_ID_SSC0,
	AT91C_ID_SSC1,
	AT91C_ID_LCDC,
	AT91C_ID_ISI,
	AT91C_ID_TRNG,
	AT91C_ID_PDMIC,
	AT91C_ID_SFC,
	AT91C_ID_QSPI0,
	AT91C_ID_QSPI1,
	AT91C_ID_I2SC0,
	AT91C_ID_I2SC1,
	AT91C_ID_CAN0_INT0,
	AT91C_ID_CAN1_INT0,
	AT91C_ID_CLASSD,
	AT91C_ID_SFR,
	AT91C_ID_L2CC,
	AT91C_ID_CAN0_INT1,
	AT91C_ID_CAN1_INT1,
	AT91C_ID_GMAC_Q1,
	AT91C_ID_GMAC_Q2,
	AT91C_ID_SDMMC0_TIMER,
	AT91C_ID_SDMMC1_TIMER,
	AT91C_ID_SYS,
	AT91C_ID_ACC,
	AT91C_ID_RXLP,
	AT91C_ID_SFRBU,
	AT91C_ID_CHIPID,
};

static int matrix_init(void)
{
	matrix_write_protect_disable(matrix64_base());
	matrix_write_protect_disable(matrix32_base());

	matrix_configure_slave_h64mx();
	matrix_configure_slave_h32mx();

	return matrix_configure_peri_security(security_ps_peri_id,
					      ARRAY_SIZE(security_ps_peri_id));
}

void plat_cpu_reset_late(void)
{
	matrix_init();
}
