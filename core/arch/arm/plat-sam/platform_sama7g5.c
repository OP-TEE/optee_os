// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2024 Microchip Technology Inc.
 */

#include <assert.h>
#include <console.h>
#include <drivers/atmel_uart.h>
#include <drivers/gic.h>
#include <drivers/tzc400.h>
#include <io.h>
#include <kernel/boot.h>
#include <matrix.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <tz_matrix.h>
#include <util.h>

#define MATRIX_SAMA7G54 0

register_phys_mem_pgdir(MEM_AREA_IO_SEC, CONSOLE_UART_BASE,
			CORE_MMU_PGDIR_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, MATRIX_BASE_ADDRESS,
			CORE_MMU_PGDIR_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, TZC_BASE_ADDRESS, CORE_MMU_PGDIR_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, TZPM_BASE_ADDRESS,
			CORE_MMU_PGDIR_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GIC_INTERFACE_BASE, GICC_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GIC_DISTRIBUTOR_BASE, GICD_SIZE);

static struct matrix matrixes[] = {
	{
		.matrix = MATRIX_SAMA7G54,
		.p = { .pa = MATRIX_BASE_ADDRESS, },
	},
};

static struct peri_security peri_security_array[] = {
	{
		.peri_id = ID_DWDT_SW,
		.security_type = SECURITY_TYPE_AS,
		.addr = DWDT_BASE_ADDRESS,
	},
	{
		.peri_id = ID_DWDT_NSW,
		.security_type = SECURITY_TYPE_NS,
		.addr = DWDT_BASE_ADDRESS,
	},
	{
		.peri_id = ID_DWDT_NSW_ALARM,
		.security_type = SECURITY_TYPE_AS,
		.addr = DWDT_BASE_ADDRESS,
	},
	{
		.peri_id = ID_SCKC,
		.security_type = SECURITY_TYPE_AS,
		.addr = SCKC_BASE_ADDRESS,
	},
	{
		.peri_id = ID_SHDWC,
		.security_type = SECURITY_TYPE_AS,
		.addr = SHDWC_BASE_ADDRESS,
	},
	{
		.peri_id = ID_RSTC,
		.security_type = SECURITY_TYPE_AS,
		.addr = RSTC_BASE_ADDRESS,
	},
	{
		.peri_id = ID_RTC,
		.security_type = SECURITY_TYPE_AS,
		.addr = RTC_BASE_ADDRESS,
	},
	{
		.peri_id = ID_RTT,
		.security_type = SECURITY_TYPE_AS,
		.addr = RTT_BASE_ADDRESS,
	},
	{
		.peri_id = ID_CHIPID,
		.security_type = SECURITY_TYPE_PS,
		.addr = CHIPID_BASE_ADDRESS,
	},
	{
		.peri_id = ID_PMC,
		.security_type = SECURITY_TYPE_AS,
		.addr = PMC_BASE_ADDRESS,
	},
	{
		.peri_id = ID_PIOA,
		.security_type = SECURITY_TYPE_PS,
		.addr = PIO_BASE_ADDRESS,
	},
	{
		.peri_id = ID_PIOB,
		.security_type = SECURITY_TYPE_PS,
		.addr = PIO_BASE_ADDRESS + 0x40,
	},
	{
		.peri_id = ID_PIOC,
		.security_type = SECURITY_TYPE_PS,
		.addr = PIO_BASE_ADDRESS + 0x80,
	},
	{
		.peri_id = ID_PIOD,
		.security_type = SECURITY_TYPE_PS,
		.addr = PIO_BASE_ADDRESS + 0xC0,
	},
	{
		.peri_id = ID_PIOE,
		.security_type = SECURITY_TYPE_PS,
		.addr = PIO_BASE_ADDRESS + 0x100,
	},
	{
		.peri_id = ID_SECUMOD,
		.security_type = SECURITY_TYPE_AS,
		.addr = SECUMOD_BASE_ADDRESS,
	},
	{
		.peri_id = ID_SECURAM,
		.security_type = SECURITY_TYPE_AS,
		.addr = 0xE0000000,
	},
	{
		.peri_id = ID_SFR,
		.security_type = SECURITY_TYPE_PS,
		.addr = SFR_BASE_ADDRESS,
	},
	{
		.peri_id = ID_SFRBU,
		.security_type = SECURITY_TYPE_AS,
		.addr = SFRBU_BASE_ADDRESS,
	},
	{
		.peri_id = ID_HSMC,
		.security_type = SECURITY_TYPE_PS,
		.addr = HSMC_BASE_ADDRESS,
	},
	{
		.peri_id = ID_XDMAC0,
		.security_type = SECURITY_TYPE_PS,
		.addr = XDMAC0_BASE_ADDRESS,
	},
	{
		.peri_id = ID_XDMAC1,
		.security_type = SECURITY_TYPE_PS,
		.addr = XDMAC1_BASE_ADDRESS,
	},
	{
		.peri_id = ID_XDMAC2,
		.security_type = SECURITY_TYPE_PS,
		.addr = XDMAC2_BASE_ADDRESS,
	},
	{
		.peri_id = ID_ACC,
		.security_type = SECURITY_TYPE_PS,
		.addr = ACC_BASE_ADDRESS,
	},
	{
		.peri_id = ID_ADC,
		.security_type = SECURITY_TYPE_PS,
		.addr = ADC_BASE_ADDRESS,
	},
	{
		.peri_id = ID_AES,
		.security_type = SECURITY_TYPE_PS,
		.addr = AES_BASE_ADDRESS,
	},
	{
		.peri_id = ID_TZAESBASC,
		.security_type = SECURITY_TYPE_AS,
		.addr = TZAESBASC_BASE_ADDRESS,
	},
	{
		.peri_id = ID_ASRC,
		.security_type = SECURITY_TYPE_PS,
		.addr = ASRC_BASE_ADDRESS,
	},
	{
		.peri_id = ID_CPKCC,
		.security_type = SECURITY_TYPE_PS,
		.addr = CPKCC_BASE_ADDRESS,
	},
	{
		.peri_id = ID_CSI,
		.security_type = SECURITY_TYPE_PS,
		.addr = CSI_BASE_ADDRESS,
	},
	{
		.peri_id = ID_CSI2DC,
		.security_type = SECURITY_TYPE_PS,
		.addr = CSI2DC_BASE_ADDRESS,
	},
	{
		.peri_id = ID_DDRPUBL,
		.security_type = SECURITY_TYPE_PS,
		.addr = DDRPUBL_BASE_ADDRESS,
	},
	{
		.peri_id = ID_DDRUMCTL,
		.security_type = SECURITY_TYPE_PS,
		.addr = DDRUMCTL_BASE_ADDRESS,
	},
	{
		.peri_id = ID_EIC,
		.security_type = SECURITY_TYPE_PS,
		.addr = EIC_BASE_ADDRESS,
	},
	{
		.peri_id = ID_FLEXCOM0,
		.security_type = SECURITY_TYPE_PS,
		.addr = FLEXCOM0_BASE_ADDRESS,
	},
	{
		.peri_id = ID_FLEXCOM1,
		.security_type = SECURITY_TYPE_PS,
		.addr = FLEXCOM1_BASE_ADDRESS,
	},
	{
		.peri_id = ID_FLEXCOM2,
		.security_type = SECURITY_TYPE_PS,
		.addr = FLEXCOM2_BASE_ADDRESS,
	},
	{
		.peri_id = ID_FLEXCOM3,
		.security_type = SECURITY_TYPE_PS,
		.addr = FLEXCOM3_BASE_ADDRESS,
	},
	{
		.peri_id = ID_FLEXCOM4,
		.security_type = SECURITY_TYPE_PS,
		.addr = FLEXCOM4_BASE_ADDRESS,
	},
	{
		.peri_id = ID_FLEXCOM5,
		.security_type = SECURITY_TYPE_PS,
		.addr = FLEXCOM5_BASE_ADDRESS,
	},
	{
		.peri_id = ID_FLEXCOM6,
		.security_type = SECURITY_TYPE_PS,
		.addr = FLEXCOM6_BASE_ADDRESS,
	},
	{
		.peri_id = ID_FLEXCOM7,
		.security_type = SECURITY_TYPE_PS,
		.addr = FLEXCOM7_BASE_ADDRESS,
	},
	{
		.peri_id = ID_FLEXCOM8,
		.security_type = SECURITY_TYPE_PS,
		.addr = FLEXCOM8_BASE_ADDRESS,
	},
	{
		.peri_id = ID_FLEXCOM9,
		.security_type = SECURITY_TYPE_PS,
		.addr = FLEXCOM9_BASE_ADDRESS,
	},
	{
		.peri_id = ID_FLEXCOM10,
		.security_type = SECURITY_TYPE_PS,
		.addr = FLEXCOM10_BASE_ADDRESS,
	},
	{
		.peri_id = ID_FLEXCOM11,
		.security_type = SECURITY_TYPE_PS,
		.addr = FLEXCOM11_BASE_ADDRESS,
	},
	{
		.peri_id = ID_GMAC0,
		.security_type = SECURITY_TYPE_PS,
		.addr = GMAC0_BASE_ADDRESS,
	},
	{
		.peri_id = ID_GMAC1,
		.security_type = SECURITY_TYPE_PS,
		.addr = GMAC1_BASE_ADDRESS,
	},
	{
		.peri_id = ID_GMAC0_TSU,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = ID_GMAC1_TSU,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = ID_ICM,
		.security_type = SECURITY_TYPE_AS,
		.addr = ICM_BASE_ADDRESS,
	},
	{
		.peri_id = ID_ISC,
		.security_type = SECURITY_TYPE_PS,
		.addr = ISC_BASE_ADDRESS,
	},
	{
		.peri_id = ID_I2SMCC0,
		.security_type = SECURITY_TYPE_PS,
		.addr = I2SMCC0_BASE_ADDRESS,
	},
	{
		.peri_id = ID_I2SMCC1,
		.security_type = SECURITY_TYPE_PS,
		.addr = I2SMCC1_BASE_ADDRESS,
	},
	{
		.peri_id = ID_MATRIX,
		.security_type = SECURITY_TYPE_AS,
		.addr = MATRIX_BASE_ADDRESS,
	},
	{
		.peri_id = ID_MCAN0,
		.security_type = SECURITY_TYPE_PS,
		.addr = MCAN0_BASE_ADDRESS,
	},
	{
		.peri_id = ID_MCAN1,
		.security_type = SECURITY_TYPE_PS,
		.addr = MCAN1_BASE_ADDRESS,
	},
	{
		.peri_id = ID_MCAN2,
		.security_type = SECURITY_TYPE_PS,
		.addr = MCAN2_BASE_ADDRESS,
	},
	{
		.peri_id = ID_MCAN3,
		.security_type = SECURITY_TYPE_PS,
		.addr = MCAN3_BASE_ADDRESS,
	},
	{
		.peri_id = ID_MCAN4,
		.security_type = SECURITY_TYPE_PS,
		.addr = MCAN4_BASE_ADDRESS,
	},
	{
		.peri_id = ID_MCAN5,
		.security_type = SECURITY_TYPE_PS,
		.addr = MCAN5_BASE_ADDRESS,
	},
	{
		.peri_id = ID_OTPC,
		.security_type = SECURITY_TYPE_PS,
		.addr = OTPC_BASE_ADDRESS,
	},
	{
		.peri_id = ID_PDMC0,
		.security_type = SECURITY_TYPE_PS,
		.addr = PDMC0_BASE_ADDRESS,
	},
	{
		.peri_id = ID_PDMC1,
		.security_type = SECURITY_TYPE_PS,
		.addr = PDMC1_BASE_ADDRESS,
	},
	{
		.peri_id = ID_PIT64B0,
		.security_type = SECURITY_TYPE_PS,
		.addr = PIT64B0_BASE_ADDRESS,
	},
	{
		.peri_id = ID_PIT64B1,
		.security_type = SECURITY_TYPE_PS,
		.addr = PIT64B1_BASE_ADDRESS,
	},
	{
		.peri_id = ID_PIT64B2,
		.security_type = SECURITY_TYPE_PS,
		.addr = PIT64B2_BASE_ADDRESS,
	},
	{
		.peri_id = ID_PIT64B3,
		.security_type = SECURITY_TYPE_PS,
		.addr = PIT64B3_BASE_ADDRESS,
	},
	{
		.peri_id = ID_PIT64B4,
		.security_type = SECURITY_TYPE_PS,
		.addr = PIT64B4_BASE_ADDRESS,
	},
	{
		.peri_id = ID_PIT64B5,
		.security_type = SECURITY_TYPE_PS,
		.addr = PIT64B5_BASE_ADDRESS,
	},
	{
		.peri_id = ID_PWM,
		.security_type = SECURITY_TYPE_PS,
		.addr = PWM_BASE_ADDRESS,
	},
	{
		.peri_id = ID_QSPI0,
		.security_type = SECURITY_TYPE_PS,
		.addr = QSPI0_BASE_ADDRESS,
	},
	{
		.peri_id = ID_QSPI1,
		.security_type = SECURITY_TYPE_PS,
		.addr = QSPI1_BASE_ADDRESS,
	},
	{
		.peri_id = ID_SDMMC0,
		.security_type = SECURITY_TYPE_PS,
		.addr = SDMMC0_BASE_ADDRESS,
	},
	{
		.peri_id = ID_SDMMC1,
		.security_type = SECURITY_TYPE_PS,
		.addr = SDMMC1_BASE_ADDRESS,
	},
	{
		.peri_id = ID_SDMMC2,
		.security_type = SECURITY_TYPE_PS,
		.addr = SDMMC2_BASE_ADDRESS,
	},
	{
		.peri_id = ID_SHA,
		.security_type = SECURITY_TYPE_PS,
		.addr = SHA_BASE_ADDRESS,
	},
	{
		.peri_id = ID_SPDIFRX,
		.security_type = SECURITY_TYPE_PS,
		.addr = SPDIFRX_BASE_ADDRESS,
	},
	{
		.peri_id = ID_SPDIFTX,
		.security_type = SECURITY_TYPE_PS,
		.addr = SPDIFTX_BASE_ADDRESS,
	},
	{
		.peri_id = ID_SSC0,
		.security_type = SECURITY_TYPE_PS,
		.addr = SSC0_BASE_ADDRESS,
	},
	{
		.peri_id = ID_SSC1,
		.security_type = SECURITY_TYPE_PS,
		.addr = SSC1_BASE_ADDRESS,
	},
	{
		.peri_id = ID_TC0_CHANNEL0,
		.security_type = SECURITY_TYPE_PS,
		.addr = TC0_BASE_ADDRESS,
	},
	{
		.peri_id = ID_TC0_CHANNEL1,
		.security_type = SECURITY_TYPE_PS,
		.addr = TC0_BASE_ADDRESS + 0x40,
	},
	{
		.peri_id = ID_TC0_CHANNEL2,
		.security_type = SECURITY_TYPE_PS,
		.addr = TC0_BASE_ADDRESS + 0x80,
	},
	{
		.peri_id = ID_TC1_CHANNEL0,
		.security_type = SECURITY_TYPE_PS,
		.addr = TC1_BASE_ADDRESS,
	},
	{
		.peri_id = ID_TC1_CHANNEL1,
		.security_type = SECURITY_TYPE_PS,
		.addr = TC1_BASE_ADDRESS + 0x40,
	},
	{
		.peri_id = ID_TC1_CHANNEL2,
		.security_type = SECURITY_TYPE_PS,
		.addr = TC1_BASE_ADDRESS + 0x80,
	},
	{
		.peri_id = ID_TCPCA,
		.security_type = SECURITY_TYPE_PS,
		.addr = TCPCA_BASE_ADDRESS,
	},
	{
		.peri_id = ID_TCPCB,
		.security_type = SECURITY_TYPE_PS,
		.addr = TCPCB_BASE_ADDRESS,
	},
	{
		.peri_id = ID_TDES,
		.security_type = SECURITY_TYPE_PS,
		.addr = TDES_BASE_ADDRESS,
	},
	{
		.peri_id = ID_TRNG,
		.security_type = SECURITY_TYPE_PS,
		.addr = TRNG_BASE_ADDRESS,
	},
	{
		.peri_id = ID_TZAESB_NS,
		.security_type = SECURITY_TYPE_PS,
		.addr = TZAESBNS_BASE_ADDRESS,
	},
	{
		.peri_id = ID_TZAESB_NS_SINT,
		.security_type = SECURITY_TYPE_AS,
		.addr = TZAESBNS_BASE_ADDRESS,},
	{
		.peri_id = ID_TZAESB_S,
		.security_type = SECURITY_TYPE_PS,
		.addr = TZAESBS_BASE_ADDRESS,
	},
	{
		.peri_id = ID_TZAESB_S_SINT,
		.security_type = SECURITY_TYPE_AS,
		.addr = TZAESBS_BASE_ADDRESS,
	},
	{
		.peri_id = ID_TZC,
		.security_type = SECURITY_TYPE_AS,
		.addr = TZC_BASE_ADDRESS,
	},
	{
		.peri_id = ID_TZPM,
		.security_type = SECURITY_TYPE_PS,
		.addr = TZPM_BASE_ADDRESS,
	},
	{
		.peri_id = ID_UDPHSA,
		.security_type = SECURITY_TYPE_PS,
		.addr = UDPHSA_BASE_ADDRESS,
	},
	{
		.peri_id = ID_UDPHSB,
		.security_type = SECURITY_TYPE_PS,
		.addr = UDPHSB_BASE_ADDRESS,
	},
	{
		.peri_id = ID_UHPHS,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = ID_XDMAC0_SINT,
		.security_type = SECURITY_TYPE_PS,
		.addr = XDMAC0_BASE_ADDRESS,
	},
	{
		.peri_id = ID_XDMAC1_SINT,
		.security_type = SECURITY_TYPE_PS,
		.addr = XDMAC1_BASE_ADDRESS,
	},
	{
		.peri_id = ID_XDMAC2_SINT,
		.security_type = SECURITY_TYPE_PS,
		.addr = XDMAC2_BASE_ADDRESS,
	},
	{
		.peri_id = ID_AES_SINT,
		.security_type = SECURITY_TYPE_PS,
		.addr = AES_BASE_ADDRESS,
	},
	{
		.peri_id = ID_GMAC0_Q1,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = ID_GMAC0_Q2,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = ID_GMAC0_Q3,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = ID_GMAC0_Q4,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = ID_GMAC0_Q5,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = ID_GMAC1_Q1,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = ID_ICM_SINT,
		.security_type = SECURITY_TYPE_AS,
		.addr = ICM_BASE_ADDRESS,
	},
	{
		.peri_id = ID_MCAN0_INT1,
		.security_type = SECURITY_TYPE_PS,
		.addr = MCAN0_BASE_ADDRESS,
	},
	{
		.peri_id = ID_MCAN1_INT1,
		.security_type = SECURITY_TYPE_PS,
		.addr = MCAN1_BASE_ADDRESS,
	},
	{
		.peri_id = ID_MCAN2_INT1,
		.security_type = SECURITY_TYPE_PS,
		.addr = MCAN2_BASE_ADDRESS,
	},
	{
		.peri_id = ID_MCAN3_INT1,
		.security_type = SECURITY_TYPE_PS,
		.addr = MCAN3_BASE_ADDRESS,
	},
	{
		.peri_id = ID_MCAN4_INT1,
		.security_type = SECURITY_TYPE_PS,
		.addr = MCAN4_BASE_ADDRESS,
	},
	{
		.peri_id = ID_MCAN5_INT1,
		.security_type = SECURITY_TYPE_PS,
		.addr = MCAN5_BASE_ADDRESS,
	},
	{
		.peri_id = ID_PIOA_SINT,
		.security_type = SECURITY_TYPE_PS,
		.addr = PIO_BASE_ADDRESS,
	},
	{
		.peri_id = ID_PIOB_SINT,
		.security_type = SECURITY_TYPE_PS,
		.addr = PIO_BASE_ADDRESS + 0x40,
	},
	{
		.peri_id = ID_PIOC_SINT,
		.security_type = SECURITY_TYPE_PS,
		.addr = PIO_BASE_ADDRESS + 0x80,
	},
	{
		.peri_id = ID_PIOD_SINT,
		.security_type = SECURITY_TYPE_PS,
		.addr = PIO_BASE_ADDRESS + 0xC0,
	},
	{
		.peri_id = ID_PIOE_SINT,
		.security_type = SECURITY_TYPE_PS,
		.addr = PIO_BASE_ADDRESS + 0x100,
	},
	{
		.peri_id = ID_PIT64B0_SINT,
		.security_type = SECURITY_TYPE_PS,
		.addr = PIT64B0_BASE_ADDRESS,
	},
	{
		.peri_id = ID_PIT64B1_SINT,
		.security_type = SECURITY_TYPE_PS,
		.addr = PIT64B1_BASE_ADDRESS,
	},
	{
		.peri_id = ID_PIT64B2_SINT,
		.security_type = SECURITY_TYPE_PS,
		.addr = PIT64B2_BASE_ADDRESS,
	},
	{
		.peri_id = ID_PIT64B3_SINT,
		.security_type = SECURITY_TYPE_PS,
		.addr = PIT64B3_BASE_ADDRESS,
	},
	{
		.peri_id = ID_PIT64B4_SINT,
		.security_type = SECURITY_TYPE_PS,
		.addr = PIT64B4_BASE_ADDRESS,
	},
	{
		.peri_id = ID_PIT64B5_SINT,
		.security_type = SECURITY_TYPE_PS,
		.addr = PIT64B5_BASE_ADDRESS,
	},
	{
		.peri_id = ID_SDMMC0_TIMER,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = ID_SDMMC1_TIMER,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = ID_SDMMC2_TIMER,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = ID_SHA_SINT,
		.security_type = SECURITY_TYPE_PS,
		.addr = SHA_BASE_ADDRESS,
	},
	{
		.peri_id = ID_TC0_SINT0,
		.security_type = SECURITY_TYPE_PS,
		.addr = TC0_BASE_ADDRESS,
	},
	{
		.peri_id = ID_TC0_SINT1,
		.security_type = SECURITY_TYPE_PS,
		.addr = TC0_BASE_ADDRESS,
	},
	{
		.peri_id = ID_TC0_SINT2,
		.security_type = SECURITY_TYPE_PS,
		.addr = TC0_BASE_ADDRESS,
	},
	{
		.peri_id = ID_TC1_SINT0,
		.security_type = SECURITY_TYPE_PS,
		.addr = TC1_BASE_ADDRESS,
	},
	{
		.peri_id = ID_TC1_SINT1,
		.security_type = SECURITY_TYPE_PS,
		.addr = TC1_BASE_ADDRESS,
	},
	{
		.peri_id = ID_TC1_SINT2,
		.security_type = SECURITY_TYPE_PS,
		.addr = TC1_BASE_ADDRESS,
	},
	{
		.peri_id = ID_TDES_SINT,
		.security_type = SECURITY_TYPE_PS,
		.addr = TDES_BASE_ADDRESS,
	},
	{
		.peri_id = ID_TRNG_SINT,
		.security_type = SECURITY_TYPE_PS,
		.addr = TRNG_BASE_ADDRESS,
	},
	{
		.peri_id = ID_EXT_IRQ0,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = ID_EXT_IRQ1,
		.security_type = SECURITY_TYPE_PS,
	},
};

static struct atmel_uart_data console_data;

void plat_console_init(void)
{
	atmel_uart_init(&console_data, CONSOLE_UART_BASE);
	register_serial_console(&console_data.chip);
}

struct peri_security *peri_security_get(unsigned int idx)
{
	struct peri_security *p = NULL;

	if (idx < ARRAY_SIZE(peri_security_array))
		p = &peri_security_array[idx];

	return p;
}

struct matrix *matrix_get(unsigned int idx)
{
	struct matrix *p = NULL;

	if (idx < ARRAY_SIZE(matrixes))
		p = &matrixes[idx];

	return p;
}

static void matrix_configure_slave(void)
{
	unsigned int sasplit_setting = 0;
	unsigned int srtop_setting = 0;
	unsigned int ssr_setting = 0;
	unsigned int base = 0;

	static_assert(CFG_TZDRAM_START == DDR_CS_ADDR);
	static_assert(CFG_TZDRAM_SIZE == 0x800000);

	base = matrix_base(MATRIX_SAMA7G54);

	/* 0: QSPI0: Normal world */
	/* 1: QSPI1: Normal world */
	srtop_setting = MATRIX_SRTOP(0, MATRIX_SRTOP_VALUE_128M) |
			MATRIX_SRTOP(1, MATRIX_SRTOP_VALUE_128M);
	sasplit_setting = MATRIX_SASPLIT(0, MATRIX_SASPLIT_VALUE_128M) |
			  MATRIX_SASPLIT(1, MATRIX_SASPLIT_VALUE_128M);
	ssr_setting = MATRIX_LANSECH_NS(0) |
		      MATRIX_LANSECH_NS(1) |
		      MATRIX_RDNSECH_NS(0) |
		      MATRIX_RDNSECH_NS(1) |
		      MATRIX_WRNSECH_NS(0) |
		      MATRIX_WRNSECH_NS(1);
	matrix_configure_slave_security(base, 0, srtop_setting,
					sasplit_setting, ssr_setting);
	matrix_configure_slave_security(base, 1, srtop_setting,
					sasplit_setting, ssr_setting);

	/* 2: TZAESB: Default */

	/* 3: UDDRC_P1: Non-Secure, except op-tee tee/ta memory */
	/*
	 * Matrix DDR configuration is hardcoded here and is difficult to
	 * generate at runtime. Since this configuration expect the secure
	 * DRAM to be at start of RAM and 8M of size, enforce it here.
	 */
	srtop_setting = MATRIX_SRTOP(0, MATRIX_SRTOP_VALUE_128M);
	sasplit_setting = MATRIX_SASPLIT(0, MATRIX_SASPLIT_VALUE_8M);
	ssr_setting = MATRIX_LANSECH_S(0) |
		      MATRIX_RDNSECH_S(0) |
		      MATRIX_WRNSECH_S(0);
	matrix_configure_slave_security(base, 3, srtop_setting,
					sasplit_setting, ssr_setting);

	/* 4: APB6: Default */

	/*
	 * 5: SRAM_P0
	 * 6: SRAM_P1
	 */
	srtop_setting = MATRIX_SRTOP(0, MATRIX_SRTOP_VALUE_128K);
	sasplit_setting = MATRIX_SASPLIT(0, MATRIX_SASPLIT_VALUE_64K);
	ssr_setting = MATRIX_LANSECH_NS(0) |
		      MATRIX_RDNSECH_S(0) |
		      MATRIX_WRNSECH_S(0);
	matrix_configure_slave_security(base, 5, srtop_setting,
					sasplit_setting, ssr_setting);
	matrix_configure_slave_security(base, 6, srtop_setting,
					sasplit_setting, ssr_setting);

	/*
	 * 7: SMC
	 * EBI_CS0 ----> Slave Region 0
	 * EBI_CS1 ----> Slave Region 1
	 * EBI_CS2 ----> Slave Region 2
	 * EBI_CS3 ----> Slave Region 3
	 * NFC_CMD ----> Slave Region 4 : Non-Secure
	 */
	srtop_setting =	MATRIX_SRTOP(4, MATRIX_SRTOP_VALUE_128M);
	sasplit_setting = MATRIX_SASPLIT(4, MATRIX_SASPLIT_VALUE_128M);
	ssr_setting = MATRIX_LANSECH_NS(4) |
		      MATRIX_RDNSECH_NS(4) |
		      MATRIX_WRNSECH_NS(4);
	matrix_configure_slave_security(base, 7, srtop_setting,
					sasplit_setting, ssr_setting);

	/*
	 * 8: NFC_RAM
	 * Slave area below SASSPLIT boundary is configured as Not Secured
	 */
	srtop_setting = MATRIX_SRTOP(0, MATRIX_SRTOP_VALUE_8K);
	sasplit_setting = MATRIX_SASPLIT(0, MATRIX_SASPLIT_VALUE_8K);
	ssr_setting = MATRIX_LANSECH_NS(0);
	matrix_configure_slave_security(base, 8, srtop_setting,
					sasplit_setting, ssr_setting);

	/*
	 * 9: USB_RAM
	 * Slave area below SASSPLIT boundary is configured as Not Secured
	 */
	srtop_setting = MATRIX_SRTOP(0, MATRIX_SRTOP_VALUE_1M) |
			MATRIX_SRTOP(1, MATRIX_SRTOP_VALUE_1M) |
			MATRIX_SRTOP(2, MATRIX_SRTOP_VALUE_4K) |
			MATRIX_SRTOP(3, MATRIX_SRTOP_VALUE_4K);
	sasplit_setting = MATRIX_SASPLIT(0, MATRIX_SASPLIT_VALUE_1M) |
			  MATRIX_SASPLIT(1, MATRIX_SASPLIT_VALUE_1M) |
			  MATRIX_SASPLIT(2, MATRIX_SASPLIT_VALUE_4K) |
			  MATRIX_SASPLIT(3, MATRIX_SASPLIT_VALUE_4K);
	ssr_setting = MATRIX_LANSECH_NS(0) |
		      MATRIX_LANSECH_NS(1) |
		      MATRIX_LANSECH_NS(2) |
		      MATRIX_LANSECH_NS(3);
	matrix_configure_slave_security(base, 9, srtop_setting,
					sasplit_setting, ssr_setting);
}

static void matrix_init(void)
{
	matrix_write_protect_disable(matrix_base(MATRIX_SAMA7G54));
	matrix_configure_slave();
}

static void tzc400_init(void)
{
	struct tzc_region_config cfg = { };
	unsigned int tzc_idx = 0;
	vaddr_t addr = 0;

	for (tzc_idx = 0; tzc_idx <= 1; tzc_idx++) {
		addr = TZC_BASE_ADDRESS + 0x1000 * tzc_idx;
		tzc_init(addr);

		if (tzc_idx)
			cfg.filters = BIT(0);
		else
			cfg.filters = GENMASK_32(3, 0);
		cfg.sec_attr = TZC_REGION_S_RDWR;

		cfg.base = 0x00000000;
		cfg.top = 0xffffffff;
		cfg.ns_device_access = BIT(16) | BIT(0);
		tzc_configure_region(0, &cfg);

		cfg.base = CFG_TZDRAM_START;
		cfg.top = cfg.base + CFG_TZDRAM_SIZE - 1;
		cfg.ns_device_access = 0;
		tzc_configure_region(1, &cfg);

		cfg.base += CFG_TZDRAM_SIZE;
		cfg.top = cfg.base - CFG_TZDRAM_SIZE + DDR_CS_SIZE - 1;
		cfg.ns_device_access = BIT(16) | BIT(0);
		tzc_configure_region(2, &cfg);
	}
}

static void tzpm_init(void)
{
	struct peri_security *p = peri_security_array;
	unsigned int i = 0;
	vaddr_t addr = TZPM_BASE_ADDRESS;

	/* TZPM_PIDx register write is possible. */
	io_write32(addr + 0x04, 0x12AC4B5D);

	for (i = 0; i < ARRAY_SIZE(peri_security_array); i++, p++)
		if (p->peri_id < 128 &&
		    p->security_type == SECURITY_TYPE_PS)
			io_setbits32(addr + 8 + 4 * (p->peri_id / 32),
				     BIT(p->peri_id % 32));
}

void plat_primary_init_early(void)
{
	assert(!cpu_mmu_enabled());
	matrix_init();
	tzc400_init();
	tzpm_init();
}

void boot_primary_init_intc(void)
{
	gic_init(GIC_INTERFACE_BASE, GIC_DISTRIBUTOR_BASE);
}
