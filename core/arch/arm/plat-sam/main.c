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
#include <drivers/atmel_saic.h>
#include <drivers/atmel_uart.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/tz_ssvce_def.h>
#include <matrix.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <sama5d2.h>
#include <stdint.h>
#include <sm/optee_smc.h>
#include <tz_matrix.h>

#define MATRIX_AXIMX   1
#define MATRIX_H64MX   2
#define MATRIX_H32MX   3

static struct matrix matrixes[] = {
	{
		.matrix = MATRIX_H64MX,
		.p = { .pa = AT91C_BASE_MATRIX64 }
	},
	{
		.matrix = MATRIX_H32MX,
		.p = { .pa = AT91C_BASE_MATRIX32, }
	}
};

static struct peri_security peri_security_array[] = {
	{
		.peri_id = AT91C_ID_PMC,
		.matrix = MATRIX_H64MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_PMC,
	},
	{
		.peri_id = AT91C_ID_ARM,
		.matrix = MATRIX_H64MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_PIT,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_PITC,
	},
	{
		.peri_id = AT91C_ID_WDT,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_WDT,
	},
	{
		.peri_id = AT91C_ID_GMAC,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_GMAC,
	},
	{
		.peri_id = AT91C_ID_XDMAC0,
		.matrix = MATRIX_H64MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_XDMAC0,
	},
	{
		.peri_id = AT91C_ID_XDMAC1,
		.matrix = MATRIX_H64MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_XDMAC1,
	},
	{
		.peri_id = AT91C_ID_ICM,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_ICM,
	},
	{
		.peri_id = AT91C_ID_AES,
		.matrix = MATRIX_H64MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_AES,
	},
	{
		.peri_id = AT91C_ID_AESB,
		.matrix = MATRIX_H64MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_AESB,
	},
	{
		.peri_id = AT91C_ID_TDES,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_TDES,
	},
	{
		.peri_id = AT91C_ID_SHA,
		.matrix = MATRIX_H64MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_SHA,
	},
	{
		.peri_id = AT91C_ID_MPDDRC,
		.matrix = MATRIX_H64MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_MPDDRC,
	},
	{
		.peri_id = AT91C_ID_MATRIX1,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_AS,
		.addr = AT91C_BASE_MATRIX32,
	},
	{
		.peri_id = AT91C_ID_MATRIX0,
		.matrix = MATRIX_H64MX,
		.security_type = SECURITY_TYPE_AS,
		.addr = AT91C_BASE_MATRIX64,
	},
	{
		.peri_id = AT91C_ID_SECUMOD,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_AS,
		.addr = AT91C_BASE_SECUMOD,
	},
	{
		.peri_id = AT91C_ID_HSMC,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_HSMC,
	},
	{
		.peri_id = AT91C_ID_PIOA,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_AS,
		.addr = AT91C_BASE_PIOA,
	},
	{
		.peri_id = AT91C_ID_FLEXCOM0,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_FLEXCOM0,
	},
	{
		.peri_id = AT91C_ID_FLEXCOM1,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_FLEXCOM1,
	},
	{
		.peri_id = AT91C_ID_FLEXCOM2,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_FLEXCOM2,
	},
	{
		.peri_id = AT91C_ID_FLEXCOM3,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_FLEXCOM3,
	},
	{
		.peri_id = AT91C_ID_FLEXCOM4,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_FLEXCOM4,
	},
	{
		.peri_id = AT91C_ID_UART0,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_UART0,
	},
	{
		.peri_id = AT91C_ID_UART1,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_UART1,
	},
	{
		.peri_id = AT91C_ID_UART2,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_UART2,
	},
	{
		.peri_id = AT91C_ID_UART3,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_UART3,
	},
	{
		.peri_id = AT91C_ID_UART4,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_UART4,
	},
	{
		.peri_id = AT91C_ID_TWI0,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_TWI0,
	},
	{
		.peri_id = AT91C_ID_TWI1,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_TWI1,
	},
	{
		.peri_id = AT91C_ID_SDMMC0,
		.matrix = MATRIX_H64MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_SDHC0,
	},
	{
		.peri_id = AT91C_ID_SDMMC1,
		.matrix = MATRIX_H64MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_SDHC1,
	},
	{
		.peri_id = AT91C_ID_SPI0,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_SPI0,
	},
	{
		.peri_id = AT91C_ID_SPI1,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_SPI1,
	},
	{
		.peri_id = AT91C_ID_TC0,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_TC0,
	},
	{
		.peri_id = AT91C_ID_TC1,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_TC1,
	},
	{
		.peri_id = AT91C_ID_PWM,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_PWMC,
	},
	{
		.peri_id = AT91C_ID_ADC,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_ADC,
	},
	{
		.peri_id = AT91C_ID_UHPHS,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_UDPHS,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_UDPHS,
	},
	{
		.peri_id = AT91C_ID_SSC0,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_SSC0,
	},
	{
		.peri_id = AT91C_ID_SSC1,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_SSC1,
	},
	{
		.peri_id = AT91C_ID_LCDC,
		.matrix = MATRIX_H64MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_LCDC,
	},
	{
		.peri_id = AT91C_ID_ISI,
		.matrix = MATRIX_H64MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_HXISI,
	},
	{
		.peri_id = AT91C_ID_TRNG,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_TRNG,
	},
	{
		.peri_id = AT91C_ID_PDMIC,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_PDMIC,
	},
	{
		.peri_id = AT91C_ID_IRQ,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_NS,
	},
	{
		.peri_id = AT91C_ID_SFC,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_SFC,
	},
	{
		.peri_id = AT91C_ID_SECURAM,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_AS,
		.addr = AT91C_BASE_SECURAM,
	},
	{
		.peri_id = AT91C_ID_QSPI0,
		.matrix = MATRIX_H64MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_QSPI0,
	},
	{
		.peri_id = AT91C_ID_QSPI1,
		.matrix = MATRIX_H64MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_QSPI1,
	},
	{
		.peri_id = AT91C_ID_I2SC0,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_I2SC0,
	},
	{
		.peri_id = AT91C_ID_I2SC1,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_I2SC1,
	},
	{
		.peri_id = AT91C_ID_CAN0_INT0,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_CAN1_INT0,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_CLASSD,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_CLASSD,
	},
	{
		.peri_id = AT91C_ID_SFR,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_SFR,
	},
	{
		.peri_id = AT91C_ID_SAIC,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_AS,
		.addr = AT91C_BASE_SAIC,
	},
	{
		.peri_id = AT91C_ID_AIC,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_NS,
		.addr = AT91C_BASE_AIC,
	},
	{
		.peri_id = AT91C_ID_L2CC,
		.matrix = MATRIX_H64MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_L2CC,
	},
	{
		.peri_id = AT91C_ID_CAN0_INT1,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_CAN1_INT1,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_GMAC_Q1,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_GMAC_Q2,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_PIOB,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_AS,
		.addr = AT91C_BASE_PIOB,
	},
	{
		.peri_id = AT91C_ID_PIOC,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_AS,
		.addr = AT91C_BASE_PIOC,
	},
	{
		.peri_id = AT91C_ID_PIOD,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_AS,
		.addr = AT91C_BASE_PIOD,
	},
	{
		.peri_id = AT91C_ID_SDMMC0_TIMER,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_SDMMC1_TIMER,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_SYS,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_SYSC,
	},
	{
		.peri_id = AT91C_ID_ACC,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_ACC,
	},
	{
		.peri_id = AT91C_ID_RXLP,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_RXLP,
	},
	{
		.peri_id = AT91C_ID_SFRBU,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_SFRBU,
	},
	{
		.peri_id = AT91C_ID_CHIPID,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
		.addr = AT91C_BASE_CHIPID,
	},
};

static struct atmel_uart_data console_data;
register_phys_mem_pgdir(MEM_AREA_IO_SEC, CONSOLE_UART_BASE,
			CORE_MMU_PGDIR_SIZE);

void plat_console_init(void)
{
	atmel_uart_init(&console_data, CONSOLE_UART_BASE);
	register_serial_console(&console_data.chip);
}

register_phys_mem_pgdir(MEM_AREA_IO_SEC, AT91C_BASE_MATRIX32,
			CORE_MMU_PGDIR_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, AT91C_BASE_MATRIX64,
			CORE_MMU_PGDIR_SIZE);

struct peri_security *peri_security_get(unsigned int idx)
{
	struct peri_security *p = NULL;

	if (idx < ARRAY_SIZE(peri_security_array))
		p = &peri_security_array[idx];

	return p;
}

struct matrix *matrix_get(unsigned int idx)
{
	struct matrix *pmatrix = NULL;

	if (idx < ARRAY_SIZE(matrixes))
		pmatrix = &matrixes[idx];

	return pmatrix;
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
	matrix_configure_slave_security(matrix_base(MATRIX_H64MX),
					H64MX_SLAVE_PERI_BRIDGE,
					srtop_setting,
					sasplit_setting,
					ssr_setting);

	/*
	 * Matrix DDR configuration is hardcoded here and is difficult to
	 * generate at runtime. Since this configuration expect the secure
	 * DRAM to be at start of RAM and 8M of size, enforce it here.
	 */
	COMPILE_TIME_ASSERT(CFG_TZDRAM_START == AT91C_BASE_DDRCS);
	COMPILE_TIME_ASSERT(CFG_TZDRAM_SIZE == 0x800000);

	/* 2 ~ 9 DDR2 Port1 ~ 7: Non-Secure, except op-tee tee/ta memory */
	srtop_setting = MATRIX_SRTOP(0, MATRIX_SRTOP_VALUE_128M);
	sasplit_setting = (MATRIX_SASPLIT(0, MATRIX_SASPLIT_VALUE_8M)
				| MATRIX_SASPLIT(1, MATRIX_SASPLIT_VALUE_128M)
				| MATRIX_SASPLIT(2, MATRIX_SASPLIT_VALUE_128M)
				| MATRIX_SASPLIT(3, MATRIX_SASPLIT_VALUE_128M));
	ssr_setting = (MATRIX_LANSECH_S(0)
			| MATRIX_LANSECH_NS(1)
			| MATRIX_LANSECH_NS(2)
			| MATRIX_LANSECH_NS(3)
			| MATRIX_RDNSECH_S(0)
			| MATRIX_RDNSECH_NS(1)
			| MATRIX_RDNSECH_NS(2)
			| MATRIX_RDNSECH_NS(3)
			| MATRIX_WRNSECH_S(0)
			| MATRIX_WRNSECH_NS(1)
			| MATRIX_WRNSECH_NS(2)
			| MATRIX_WRNSECH_NS(3));
	/* DDR port 0 not used from NWd */
	for (ddr_port = 1; ddr_port < 8; ddr_port++) {
		matrix_configure_slave_security(matrix_base(MATRIX_H64MX),
						H64MX_SLAVE_DDR2_PORT_0 +
						ddr_port, srtop_setting,
						sasplit_setting,
						ssr_setting);
	}

	/*
	 * 10: Internal SRAM 128K:
	 * - First 64K are reserved for suspend code in Secure World
	 * - Last 64K are for Non-Secure world (used by CAN)
	 */
	srtop_setting = MATRIX_SRTOP(0, MATRIX_SRTOP_VALUE_128K);
	sasplit_setting = MATRIX_SASPLIT(0, MATRIX_SRTOP_VALUE_64K);
	ssr_setting = (MATRIX_LANSECH_S(0) | MATRIX_RDNSECH_S(0) |
		       MATRIX_WRNSECH_S(0));
	matrix_configure_slave_security(matrix_base(MATRIX_H64MX),
					H64MX_SLAVE_INTERNAL_SRAM,
					srtop_setting, sasplit_setting,
					ssr_setting);

	/* 11:  Internal SRAM 128K (Cache L2): Default */

	/* 12:  QSPI0: Normal world */
	/* 13:  QSPI1: Normal world */
	srtop_setting = MATRIX_SRTOP(0, MATRIX_SRTOP_VALUE_128M);
	sasplit_setting = MATRIX_SASPLIT(0, MATRIX_SASPLIT_VALUE_128M);
	ssr_setting = MATRIX_LANSECH_NS(0) | MATRIX_RDNSECH_NS(0) |
		      MATRIX_WRNSECH_NS(0);

	matrix_configure_slave_security(matrix_base(MATRIX_H64MX),
					H64MX_SLAVE_QSPI0,
					srtop_setting, sasplit_setting,
					ssr_setting);
	matrix_configure_slave_security(matrix_base(MATRIX_H64MX),
					H64MX_SLAVE_QSPI1,
					srtop_setting, sasplit_setting,
					ssr_setting);
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
	matrix_configure_slave_security(matrix_base(MATRIX_H32MX),
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
	matrix_configure_slave_security(matrix_base(MATRIX_H32MX),
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
	matrix_configure_slave_security(matrix_base(MATRIX_H32MX),
					H32MX_USB,
					srtop_setting,
					sasplit_setting,
					ssr_setting);
}

static unsigned int security_ps_peri_id[] = {
	AT91C_ID_PMC,
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
	matrix_write_protect_disable(matrix_base(MATRIX_H64MX));
	matrix_write_protect_disable(matrix_base(MATRIX_H32MX));

	matrix_configure_slave_h64mx();
	matrix_configure_slave_h32mx();

	return matrix_configure_periph_non_secure(security_ps_peri_id,
					      ARRAY_SIZE(security_ps_peri_id));
}

void plat_primary_init_early(void)
{
	matrix_init();
}

void boot_primary_init_intc(void)
{
	if (atmel_saic_setup())
		panic("Failed to init interrupts\n");
}
