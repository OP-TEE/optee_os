/* SPDX-License-Identifier: BSD-Source-Code */
/*
 * Copyright (c) 2015, Atmel Corporation
 * Copyright (c) 2017, Timesys Corporation
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the disclaimer below.
 *
 * Atmel's name may not be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * DISCLAIMER: THIS SOFTWARE IS PROVIDED BY ATMEL "AS IS" AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT ARE
 * DISCLAIMED. IN NO EVENT SHALL ATMEL BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef SAMA5D2_H
#define SAMA5D2_H

/*
 * Peripheral identifiers/interrupts.
 */
#define AT91C_ID_FIQ		0	/* FIQ Interrupt ID */
#define AT91C_ID_PMC		1	/* Power Management Controller */
#define AT91C_ID_ARM		2	/* Performance Monitor Unit */
#define AT91C_ID_PIT		3	/* Periodic Interval Timer Interrupt */
#define AT91C_ID_WDT		4	/* Watchdog Timer Interrupt */
#define AT91C_ID_GMAC		5	/* Ethernet MAC */
#define AT91C_ID_XDMAC0		6	/* DMA Controller 0 */
#define AT91C_ID_XDMAC1		7	/* DMA Controller 1 */
#define AT91C_ID_ICM		8	/* Integrity Check Monitor */
#define AT91C_ID_AES		9	/* Advanced Encryption Standard */
#define AT91C_ID_AESB		10	/* AES bridge */
#define AT91C_ID_TDES		11	/* Triple Data Encryption Standard */
#define AT91C_ID_SHA		12	/* SHA Signature */
#define AT91C_ID_MPDDRC		13	/* MPDDR Controller */
#define AT91C_ID_MATRIX1	14	/* H32MX, 32-bit AHB Matrix */
#define AT91C_ID_MATRIX0	15	/* H64MX, 64-bit AHB Matrix */
#define AT91C_ID_SECUMOD	16	/* Secure Module */
#define AT91C_ID_HSMC		17	/* Multi-bit ECC interrupt */
#define AT91C_ID_PIOA		18	/* Parallel I/O Controller A */
#define AT91C_ID_FLEXCOM0	19	/* FLEXCOM0 */
#define AT91C_ID_FLEXCOM1	20	/* FLEXCOM1 */
#define AT91C_ID_FLEXCOM2	21	/* FLEXCOM2 */
#define AT91C_ID_FLEXCOM3	22	/* FLEXCOM3 */
#define AT91C_ID_FLEXCOM4	23	/* FLEXCOM4 */
#define AT91C_ID_UART0		24	/* UART0 */
#define AT91C_ID_UART1		25	/* UART1 */
#define AT91C_ID_UART2		26	/* UART2 */
#define AT91C_ID_UART3		27	/* UART3 */
#define AT91C_ID_UART4		28	/* UART4 */
#define AT91C_ID_TWI0		29	/* Two-wire Interface 0 */
#define AT91C_ID_TWI1		30	/* Two-wire Interface 1 */
#define AT91C_ID_SDMMC0		31	/* SDMMC Controller 0 */
#define AT91C_ID_SDMMC1		32	/* SDMMC Controller 1 */
#define AT91C_ID_SPI0		33	/* Serial Peripheral Interface 0 */
#define AT91C_ID_SPI1		34	/* Serial Peripheral Interface 1 */
#define AT91C_ID_TC0		35	/* Timer Counter 0 (ch.0,1,2) */
#define AT91C_ID_TC1		36	/* Timer Counter 1 (ch.3,4,5) */
/* 37 */
#define AT91C_ID_PWM		38	/* PWM Controller0 (ch. 0,1,2,3) */
/* 39 */
#define AT91C_ID_ADC		40	/* Touch Screen ADC Controller */
#define AT91C_ID_UHPHS		41	/* USB Host High Speed */
#define AT91C_ID_UDPHS		42	/* USB Device High Speed */
#define AT91C_ID_SSC0		43	/* Serial Synchronous Controller 0 */
#define AT91C_ID_SSC1		44	/* Serial Synchronous Controller 1 */
#define AT91C_ID_LCDC		45	/* LCD Controller */
#define AT91C_ID_ISI		46	/* Image Sensor Interface */
#define AT91C_ID_TRNG		47	/* True Random Number Generator */
#define AT91C_ID_PDMIC		48	/* PDM Interface Controller */
#define AT91C_ID_IRQ		49	/* IRQ Interrupt ID */
#define AT91C_ID_SFC		50	/* Fuse Controller */
#define AT91C_ID_SECURAM	51	/* Secure RAM */
#define AT91C_ID_QSPI0		52	/* QSPI0 */
#define AT91C_ID_QSPI1		53	/* QSPI1 */
#define AT91C_ID_I2SC0		54	/* Inter-IC Sound Controller 0 */
#define AT91C_ID_I2SC1		55	/* Inter-IC Sound Controller 1 */
#define AT91C_ID_CAN0_INT0	56	/* MCAN 0 Interrupt0 */
#define AT91C_ID_CAN1_INT0	57	/* MCAN 1 Interrupt0 */
#define AT91C_ID_PTC		58	/* Peripheral Touch Controller */
#define AT91C_ID_CLASSD		59	/* Audio Class D Amplifier */
#define AT91C_ID_SFR		60	/* Special Function Register */
#define AT91C_ID_SAIC		61	/* Secured AIC */
#define AT91C_ID_AIC		62	/* Advanced Interrupt Controller */
#define AT91C_ID_L2CC		63	/* L2 Cache Controller */
#define AT91C_ID_CAN0_INT1	64	/* MCAN 0 Interrupt1 */
#define AT91C_ID_CAN1_INT1	65	/* MCAN 1 Interrupt1 */
#define AT91C_ID_GMAC_Q1	66	/* GMAC Queue 1 Interrupt */
#define AT91C_ID_GMAC_Q2	67	/* GMAC Queue 2 Interrupt */
#define AT91C_ID_PIOB		68	/* Parallel I/O Controller B */
#define AT91C_ID_PIOC		69	/* Parallel I/O Controller C */
#define AT91C_ID_PIOD		70	/* Parallel I/O Controller D */
#define AT91C_ID_SDMMC0_TIMER	71	/* SDMMC0 Timer */
#define AT91C_ID_SDMMC1_TIMER	72	/* SDMMC1 Timer */
/* 73 */
#define AT91C_ID_SYS		74	/* System Controller Interrupt */
#define AT91C_ID_ACC		75	/* Analog Comparator */
#define AT91C_ID_RXLP		76	/* UART Low-Power */
#define AT91C_ID_SFRBU		77	/* Special Function Register BackUp */
#define AT91C_ID_CHIPID		78	/* Chip ID */

#define AT91C_ID_COUNTS		(AT91C_ID_CHIPID + 1)

/*
 * User Peripherals physical base addresses.
 */
#define AT91C_BASE_LCDC		0xf0000000
#define AT91C_BASE_XDMAC1	0xf0004000
#define AT91C_BASE_HXISI	0xf0008000
#define AT91C_BASE_MPDDRC	0xf000c000
#define AT91C_BASE_XDMAC0	0xf0010000
#define AT91C_BASE_PMC		0xf0014000
#define AT91C_BASE_MATRIX64	0xf0018000	/* MATRIX0 */
#define AT91C_BASE_AESB		0xf001c000
#define AT91C_BASE_QSPI0	0xf0020000
#define AT91C_BASE_QSPI1	0xf0024000
#define AT91C_BASE_SHA		0xf0028000
#define AT91C_BASE_AES		0xf002c000

#define AT91C_BASE_SPI0		0xf8000000
#define AT91C_BASE_SSC0		0xf8004000
#define AT91C_BASE_GMAC		0xf8008000
#define AT91C_BASE_TC0		0xf800c000
#define AT91C_BASE_TC1		0xf8010000
#define AT91C_BASE_HSMC		0xf8014000
#define AT91C_BASE_PDMIC	0xf8018000
#define AT91C_BASE_UART0	0xf801c000
#define AT91C_BASE_UART1	0xf8020000
#define AT91C_BASE_UART2	0xf8024000
#define AT91C_BASE_TWI0		0xf8028000
#define AT91C_BASE_PWMC		0xf802c000
#define AT91C_BASE_SFR		0xf8030000
#define AT91C_BASE_FLEXCOM0	0xf8034000
#define AT91C_BASE_FLEXCOM1	0xf8038000
#define AT91C_BASE_SAIC		0xf803c000
#define AT91C_BASE_ICM		0xf8040000
#define AT91C_BASE_SECURAM	0xf8044000
#define AT91C_BASE_SYSC		0xf8048000
#define AT91C_BASE_ACC		0xf804a000
#define AT91C_BASE_RXLP		0xf8049000
#define AT91C_BASE_SFC		0xf804c000
#define AT91C_BASE_I2SC0	0xf8050000
#define AT91C_BASE_CAN0		0xf8054000

#define AT91C_BASE_SPI1		0xfc000000
#define AT91C_BASE_SSC1		0xfc004000
#define AT91C_BASE_UART3	0xfc008000
#define AT91C_BASE_UART4	0xfc00c000
#define AT91C_BASE_FLEXCOM2	0xfc010000
#define AT91C_BASE_FLEXCOM3	0xfc014000
#define AT91C_BASE_FLEXCOM4	0xfc018000
#define AT91C_BASE_TRNG		0xfc01c000
#define AT91C_BASE_AIC		0xfc020000
#define AT91C_BASE_TWI1		0xfc028000
#define AT91C_BASE_UDPHS	0xfc02c000
#define AT91C_BASE_ADC		0xfc030000

#define AT91C_BASE_PIOA		0xfc038000
#define AT91C_BASE_MATRIX32	0xfc03c000	/* MATRIX1 */
#define AT91C_BASE_SECUMOD	0xfc040000
#define AT91C_BASE_TDES		0xfc044000
#define AT91C_BASE_CLASSD	0xfc048000
#define AT91C_BASE_I2SC1	0xfc04c000
#define AT91C_BASE_CAN1		0xfc050000
#define AT91C_BASE_SFRBU	0xfc05c000
#define AT91C_BASE_CHIPID	0xfc069000

/*
 * Address Memory Space
 */
#define AT91C_BASE_INTERNAL_MEM		0x00000000
#define AT91C_BASE_CS0			0x10000000
#define AT91C_BASE_DDRCS		0x20000000
#define AT91C_BASE_DDRCS_AES		0x40000000
#define AT91C_BASE_CS1			0x60000000
#define AT91C_BASE_CS2			0x70000000
#define AT91C_BASE_CS3			0x80000000
#define AT91C_BASE_QSPI0_AES_MEM	0x90000000
#define AT91C_BASE_QSPI1_AES_MEM	0x98000000
#define AT91C_BASE_SDHC0		0xa0000000
#define AT91C_BASE_SDHC1		0xb0000000
#define AT91C_BASE_NFC_CMD_REG		0xc0000000
#define AT91C_BASE_QSPI0_MEM		0xd0000000
#define AT91C_BASE_QSPI1_MEM		0xd8000000
#define AT91C_BASE_PERIPH		0xf0000000

/*
 * Internal Memories
 */
#define AT91C_BASE_ROM		0x00000000	/* ROM */
#define AT91C_BASE_ECC_ROM	0x00060000	/* ECC ROM */
#define AT91C_BASE_NFC_SRAM	0x00100000	/* NFC SRAM */
#define AT91C_BASE_SRAM0	0x00200000	/* SRAM0 */
#define AT91C_BASE_SRAM1	0x00220000	/* SRAM1 */
#define AT91C_BASE_UDPHS_SRAM	0x00300000	/* UDPHS RAM */
#define AT91C_BASE_UHP_OHCI	0x00400000	/* UHP OHCI */
#define AT91C_BASE_UHP_EHCI	0x00500000	/* UHP EHCI */
#define AT91C_BASE_AXI_MATRIX	0x00600000	/* AXI Maxtrix */
#define AT91C_BASE_DAP		0x00700000	/* DAP */
#define AT91C_BASE_PTC		0x00800000	/* PTC */
#define AT91C_BASE_L2CC		0x00A00000	/* L2CC */

/*
 * Other misc defines
 */
#define AT91C_BASE_PMECC	(AT91C_BASE_HSMC + 0x70)
#define AT91C_BASE_PMERRLOC	(AT91C_BASE_HSMC + 0x500)

#define AT91_PMECC		(AT91C_BASE_PMECC - AT91C_BASE_SYS)
#define AT91_PMERRLOC		(AT91C_BASE_PMERRLOC - AT91C_BASE_SYS)

#define AT91C_BASE_PIOB		(AT91C_BASE_PIOA + 0x40)
#define AT91C_BASE_PIOC		(AT91C_BASE_PIOB + 0x40)
#define AT91C_BASE_PIOD		(AT91C_BASE_PIOC + 0x40)

/* SYSC spawns */
#define AT91C_BASE_RSTC		AT91C_BASE_SYSC
#define AT91C_BASE_SHDC		(AT91C_BASE_SYSC + 0x10)
#define AT91C_BASE_PITC		(AT91C_BASE_SYSC + 0x30)
#define AT91C_BASE_WDT		(AT91C_BASE_SYSC + 0x40)
#define AT91C_BASE_SCKCR	(AT91C_BASE_SYSC + 0x50)
#define AT91C_BASE_RTCC		(AT91C_BASE_SYSC + 0xb0)

#define ATMEL_BASE_SMC		(AT91C_BASE_HSMC + 0x700)

#define AT91C_NUM_PIO		4
#define AT91C_NUM_TWI		2

/* AICREDIR Unlock Key */
#define AICREDIR_KEY		0xB6D81C4D

/*
 * Matrix Slaves ID
 */
/* MATRIX0(H64MX) Matrix Slaves */
/* Bridge from H64MX to AXIMX (Internal ROM, Cryto Library, PKCC RAM) */
#define H64MX_SLAVE_BRIDGE_TO_AXIMX	0
#define H64MX_SLAVE_PERI_BRIDGE		1	/* H64MX Peripheral Bridge */
#define H64MX_SLAVE_DDR2_PORT_0		2	/* DDR2 Port0-AESOTF */
#define H64MX_SLAVE_DDR2_PORT_1		3	/* DDR2 Port1 */
#define H64MX_SLAVE_DDR2_PORT_2		4	/* DDR2 Port2 */
#define H64MX_SLAVE_DDR2_PORT_3		5	/* DDR2 Port3 */
#define H64MX_SLAVE_DDR2_PORT_4		6	/* DDR2 Port4 */
#define H64MX_SLAVE_DDR2_PORT_5		7	/* DDR2 Port5 */
#define H64MX_SLAVE_DDR2_PORT_6		8	/* DDR2 Port6 */
#define H64MX_SLAVE_DDR2_PORT_7		9	/* DDR2 Port7 */
#define H64MX_SLAVE_INTERNAL_SRAM	10	/* Internal SRAM 128K */
#define H64MX_SLAVE_CACHE_L2		11	/* Internal SRAM 128K (L2) */
#define H64MX_SLAVE_QSPI0		12	/* QSPI0 */
#define H64MX_SLAVE_QSPI1		13	/* QSPI1 */
#define H64MX_SLAVE_AESB		14	/* AESB */

/* MATRIX1(H32MX) Matrix Slaves */
#define H32MX_BRIDGE_TO_H64MX		0	/* Bridge from H32MX to H64MX */
#define H32MX_PERI_BRIDGE_0		1	/* H32MX Peripheral Bridge 0 */
#define H32MX_PERI_BRIDGE_1		2	/* H32MX Peripheral Bridge 1 */
#define H32MX_EXTERNAL_EBI		3	/* External Bus Interface */
#define H32MX_NFC_CMD_REG		3	/* NFC command Register */
#define H32MX_NFC_SRAM			4	/* NFC SRAM */
#define H32MX_USB			5

#endif /* #ifndef SAMA5D2_H */
