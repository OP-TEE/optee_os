/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Header file for the Atmel DDR/SDR SDRAM Controller
 *
 * Copyright (C) 2010 Atmel Corporation
 *	Nicolas Ferre <nicolas.ferre@atmel.com>
 */

#ifndef __DRIVERS_SAM_AT91_DDRSDR_H
#define __DRIVERS_SAM_AT91_DDRSDR_H

/* Mode Register */
#define AT91_DDRSDRC_MR				0x00
/* Command Mode */
#define	AT91_DDRSDRC_MODE			SHIFT_U32(0x7, 0)
#define	AT91_DDRSDRC_MODE_NORMAL		0
#define	AT91_DDRSDRC_MODE_NOP			1
#define	AT91_DDRSDRC_MODE_PRECHARGE		2
#define	AT91_DDRSDRC_MODE_LMR			3
#define	AT91_DDRSDRC_MODE_REFRESH		4
#define	AT91_DDRSDRC_MODE_EXT_LMR		5
#define	AT91_DDRSDRC_MODE_DEEP			6

/* Refresh Timer Register */
#define AT91_DDRSDRC_RTR			0x04
/* Refresh Timer Counter */
#define	AT91_DDRSDRC_COUNT			SHIFT_U32(0xfff, 0)

/* Configuration Register */
#define AT91_DDRSDRC_CR				0x08
/* Number of Column Bits */
#define	AT91_DDRSDRC_NC				SHIFT_U32(3, 0)
#define	AT91_DDRSDRC_NC_SDR8			SHIFT_U32(0, 0)
#define	AT91_DDRSDRC_NC_SDR9			BIT(0)
#define	AT91_DDRSDRC_NC_SDR10			SHIFT_U32(2, 0)
#define	AT91_DDRSDRC_NC_SDR11			SHIFT_U32(3, 0)
#define	AT91_DDRSDRC_NC_DDR9			SHIFT_U32(0, 0)
#define	AT91_DDRSDRC_NC_DDR10			BIT(0)
#define	AT91_DDRSDRC_NC_DDR11			SHIFT_U32(2, 0)
#define	AT91_DDRSDRC_NC_DDR12			SHIFT_U32(3, 0)
/* Number of Row Bits */
#define	AT91_DDRSDRC_NR				SHIFT_U32(3, 2)
#define	AT91_DDRSDRC_NR_11			SHIFT_U32(0, 2)
#define	AT91_DDRSDRC_NR_12			BIT(2)
#define	AT91_DDRSDRC_NR_13			SHIFT_U32(2, 2)
#define	AT91_DDRSDRC_NR_14			SHIFT_U32(3, 2)
/* CAS Latency */
#define	AT91_DDRSDRC_CAS			SHIFT_U32(7, 4)
#define	AT91_DDRSDRC_CAS_2			SHIFT_U32(2, 4)
#define	AT91_DDRSDRC_CAS_3			SHIFT_U32(3, 4)
#define	AT91_DDRSDRC_CAS_25			SHIFT_U32(6, 4)
/* Reset DLL */
#define	AT91_DDRSDRC_RST_DLL			BIT(7)
/* Output impedance control */
#define	AT91_DDRSDRC_DICDS			BIT(8)
/* Disable DLL [SAM9 Only] */
#define	AT91_DDRSDRC_DIS_DLL			BIT(9)
/* Off-Chip Driver [SAM9 Only] */
#define	AT91_DDRSDRC_OCD			BIT(12)
/* Mask Data is Shared [SAM9 Only] */
#define	AT91_DDRSDRC_DQMS			BIT(16)
/* Active Bank X to Burst Stop Read Access Bank Y [SAM9 Only] */
#define	AT91_DDRSDRC_ACTBST			BIT(18)

/* Timing 0 Register */
#define AT91_DDRSDRC_T0PR			0x0C
/* Active to Precharge delay */
#define	AT91_DDRSDRC_TRAS			SHIFT_U32(0xf, 0)
/* Row to Column delay */
#define	AT91_DDRSDRC_TRCD			SHIFT_U32(0xf, 4)
/* Write recovery delay */
#define	AT91_DDRSDRC_TWR			SHIFT_U32(0xf, 8)
/* Row cycle delay */
#define	AT91_DDRSDRC_TRC			SHIFT_U32(0xf, 12)
/* Row precharge delay */
#define	AT91_DDRSDRC_TRP			SHIFT_U32(0xf, 16)
/* Active BankA to BankB */
#define	AT91_DDRSDRC_TRRD			SHIFT_U32(0xf, 20)
/* Internal Write to Read delay */
#define	AT91_DDRSDRC_TWTR			SHIFT_U32(0x7, 24)
/* Reduce Write to Read Delay [SAM9 Only] */
#define	AT91_DDRSDRC_RED_WRRD			SHIFT_U32(0x1, 27)
/* Load mode to active/refresh delay */
#define	AT91_DDRSDRC_TMRD			SHIFT_U32(0xf, 28)

/* Timing 1 Register */
#define AT91_DDRSDRC_T1PR			0x10
/* Row Cycle Delay */
#define	AT91_DDRSDRC_TRFC			SHIFT_U32(0x1f, 0)
/* Exit self-refresh to non-read */
#define	AT91_DDRSDRC_TXSNR			SHIFT_U32(0xff, 8)
/* Exit self-refresh to read */
#define	AT91_DDRSDRC_TXSRD			SHIFT_U32(0xff, 16)
/* Exit power-down delay */
#define	AT91_DDRSDRC_TXP			SHIFT_U32(0xf, 24)

/* Timing 2 Register [SAM9 Only] */
#define AT91_DDRSDRC_T2PR			0x14
/* Exit active power down delay to read command in mode "Fast Exit" */
#define	AT91_DDRSDRC_TXARD			SHIFT_U32(0xf, 0)
/* Exit active power down delay to read command in mode "Slow Exit" */
#define	AT91_DDRSDRC_TXARDS			SHIFT_U32(0xf, 4)
/* Row Precharge All delay */
#define	AT91_DDRSDRC_TRPA			SHIFT_U32(0xf, 8)
/* Read to Precharge delay */
#define	AT91_DDRSDRC_TRTP			SHIFT_U32(0x7, 12)

/* Low Power Register */
#define AT91_DDRSDRC_LPR			0x1C
/* Low-power Configurations */
#define	AT91_DDRSDRC_LPCB			SHIFT_U32(3, 0)
#define	AT91_DDRSDRC_LPCB_DISABLE		0
#define	AT91_DDRSDRC_LPCB_SELF_REFRESH		1
#define	AT91_DDRSDRC_LPCB_POWER_DOWN		2
#define	AT91_DDRSDRC_LPCB_DEEP_POWER_DOWN	3
/* Clock Frozen */
#define	AT91_DDRSDRC_CLKFR			BIT(2)
/* LPDDR Power Off */
#define	AT91_DDRSDRC_LPDDR2_PWOFF		BIT(3)
/* Partial Array Self Refresh */
#define	AT91_DDRSDRC_PASR			SHIFT_U32(7, 4)
/* Temperature Compensated Self Refresh */
#define	AT91_DDRSDRC_TCSR			SHIFT_U32(3, 8)
/* Drive Strength */
#define	AT91_DDRSDRC_DS				SHIFT_U32(3, 10)
/* Time to define when Low Power Mode is enabled */
#define	AT91_DDRSDRC_TIMEOUT			SHIFT_U32(3, 12)
#define	AT91_DDRSDRC_TIMEOUT_0_CLK_CYCLES	SHIFT_U32(0, 12)
#define	AT91_DDRSDRC_TIMEOUT_64_CLK_CYCLES	BIT(12)
#define	AT91_DDRSDRC_TIMEOUT_128_CLK_CYCLES	SHIFT_U32(2, 12)
/* Active power down exit time */
#define	AT91_DDRSDRC_APDE			BIT(16)
/* Update load mode register and extended mode register */
#define	AT91_DDRSDRC_UPD_MR			SHIFT_U32(3, 20)

/* Memory Device Register */
#define AT91_DDRSDRC_MDR			0x20
/* Memory Device Type */
#define	AT91_DDRSDRC_MD				SHIFT_U32(7, 0)
#define	AT91_DDRSDRC_MD_SDR			0
#define	AT91_DDRSDRC_MD_LOW_POWER_SDR		1
#define	AT91_DDRSDRC_MD_LOW_POWER_DDR		3
#define	AT91_DDRSDRC_MD_LPDDR3			5
/* [SAM9 Only] */
#define	AT91_DDRSDRC_MD_DDR2			6
#define	AT91_DDRSDRC_MD_LPDDR2			7
/* Data Bus Width */
#define AT91_DDRSDRC_DBW			BIT(4)
#define	AT91_DDRSDRC_DBW_32BITS			SHIFT_U32(0, 4)
#define	AT91_DDRSDRC_DBW_16BITS			BIT(4)

/* DLL Information Register */
#define AT91_DDRSDRC_DLL			0x24
/* Master Delay increment */
#define	AT91_DDRSDRC_MDINC			BIT(0)
/* Master Delay decrement */
#define	AT91_DDRSDRC_MDDEC			BIT(1)
/* Master Delay Overflow */
#define	AT91_DDRSDRC_MDOVF			BIT(2)
/* Master Delay value */
#define	AT91_DDRSDRC_MDVAL			SHIFT_U32(0xff, 8)

/* High Speed Register [SAM9 Only] */
#define AT91_DDRSDRC_HS				0x2C
/* Anticip read access is disabled */
#define	AT91_DDRSDRC_DIS_ATCP_RD		BIT(2)

/* Delay I/O Register n */
#define AT91_DDRSDRC_DELAY(n)			(0x30 + (0x4 * (n)))

/* Write Protect Mode Register [SAM9 Only] */
#define AT91_DDRSDRC_WPMR			0xE4
/* Write protect enable */
#define	AT91_DDRSDRC_WP				BIT(0)
/* Write protect key */
#define	AT91_DDRSDRC_WPKEY			SHIFT_U32(0xffffff, 8)
/* Write protect key = "DDR" */
#define	AT91_DDRSDRC_KEY			SHIFT_U32(0x444452, 8)

/* Write Protect Status Register [SAM9 Only] */
#define AT91_DDRSDRC_WPSR			0xE8
/* Write protect violation status */
#define	AT91_DDRSDRC_WPVS			BIT(0)
/* Write protect violation source */
#define	AT91_DDRSDRC_WPVSRC			SHIFT_U32(0xffff, 8)

#endif
