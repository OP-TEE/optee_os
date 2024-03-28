/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Microchip SAMA7 UDDR Controller and DDR3 PHY Controller registers offsets
 * and bit definitions.
 *
 * Copyright (C) [2024] Microchip Technology Inc. and its subsidiaries
 *
 * Author: Tony Han <tony.han@microchip.com>
 */

#ifndef __SAMA7_DDR_H__
#define __SAMA7_DDR_H__

/* DDR3PHY */
/* DDR3PHY PHY Initialization Register */
#define DDR3PHY_PIR		0x04
#define DDR3PHY_PIR_DLLBYP	BIT(17)	/* DLL Bypass */
#define DDR3PHY_PIR_ITMSRST	BIT(4)	/* Interface Timing Module Soft Reset */
#define DDR3PHY_PIR_DLLLOCK	BIT(2)	/* DLL Lock */
#define DDR3PHY_PIR_DLLSRST	BIT(1)	/* DLL Soft Rest */
#define DDR3PHY_PIR_INIT	BIT(0)	/* Initialization Trigger */

/* DDR3PHY PHY General Configuration Register */
#define DDR3PHY_PGCR		0x08
#define DDR3PHY_PGCR_CKDV1	BIT(13)	/* CK# Disable Value */
#define DDR3PHY_PGCR_CKDV0	BIT(12)	/* CK Disable Value */

/* DDR3PHY PHY General Status Register */
#define DDR3PHY_PGSR		0x0C
#define DDR3PHY_PGSR_IDONE	BIT(0)	/* Initialization Done */

/* DDR3PHY AC DLL Control Register */
#define DDR3PHY_ACDLLCR		0x14
#define DDR3PHY_ACDLLCR_DLLSRST BIT(30)	/* DLL Soft Reset */

/* DDR3PHY AC I/O Configuration Register */
#define DDR3PHY_ACIOCR			0x24
#define DDR3PHY_ACIOCR_CSPDD_CS0	BIT(18)	/* CS#[0] Power Down Driver */
#define DDR3PHY_ACIOCR_CKPDD_CK0	BIT(8)	/* CK[0] Power Down Driver */
#define DDR3PHY_ACIORC_ACPDD		BIT(3)	/* AC Power Down Driver */

/* DDR3PHY DATX8 Common Configuration Register */
#define DDR3PHY_DXCCR			0x28
#define DDR3PHY_DXCCR_DXPDR		BIT(3)	/* Data Power Down Receiver */

/* DDR3PHY DDR System General Configuration Register */
#define DDR3PHY_DSGCR			0x2C
#define DDR3PHY_DSGCR_ODTPDD_ODT0	BIT(20)	/* ODT[0] Power Down Driver */

/* ZQ status register 0 */
#define DDR3PHY_ZQ0SR0			0x188
/* impedance select offset */
#define DDR3PHY_ZQ0SR0_PDO_OFF		0  /* Pull-down output */
#define DDR3PHY_ZQ0SR0_PUO_OFF		5  /* Pull-up output */
#define DDR3PHY_ZQ0SR0_PDODT_OFF	10 /* Pull-down on-die termination*/
#define DDR3PHY_ZQ0SRO_PUODT_OFF	15 /* Pull-up on-die termination */

/* DDR3PHY DATX8 DLL Control Register */
#define DDR3PHY_DX0DLLCR		0x1CC
#define DDR3PHY_DX1DLLCR		0x20C	/* DATX8 DLL Control Register */
#define DDR3PHY_DXDLLCR_DLLDIS		BIT(31)	/* DLL Disable */

/* UDDRC */
/* UDDRC Operating Mode Status Register */
#define UDDRC_STAT			0x04
/* SDRAM is not in Self-refresh */
#define UDDRC_STAT_SELFREF_TYPE_DIS	SHIFT_U32(0, 4)
/* SDRAM is in Self-refresh, which was caused by PHY Master Request */
#define UDDRC_STAT_SELFREF_TYPE_PHY	SHIFT_U32(1, 4)
/* SDRAM is in Self-refresh, which was not caused solely under
 * Automatic Self-refresh control
 */
#define UDDRC_STAT_SELFREF_TYPE_SW	SHIFT_U32(2, 4)
/* SDRAM is in Self-refresh, which was caused by Automatic Self-refresh only */
#define UDDRC_STAT_SELFREF_TYPE_AUTO	SHIFT_U32(3, 4)
#define UDDRC_STAT_SELFREF_TYPE_MSK	GENMASK_32(5, 4)
#define UDDRC_STAT_OPMODE_INIT		0
#define UDDRC_STAT_OPMODE_NORMAL	1
#define UDDRC_STAT_OPMODE_PWRDOWN	2
#define UDDRC_STAT_OPMODE_SELF_REFRESH	3
#define UDDRC_STAT_OPMODE_MSK		GENMASK_32(2, 0)

/* UDDRC Low Power Control Register */
#define UDDRC_PWRCTL			0x30
#define UDDRC_PWRCTL_SELFREF_EN		BIT(0)	/* Automatic self-refresh */
#define UDDRC_PWRCTL_SELFREF_SW		BIT(5)	/* Software self-refresh */

/* UDDRC DFI Miscellaneous Control Register */
#define UDDRC_DFIMISC			0x1B0
/* PHY initialization complete enable signal */
#define UDDRC_DFIMISC_DFI_INIT_COMPLETE_EN BIT(0)

/* UDDRC Software Register Programming Control Enable */
#define UDDRC_SWCTRL			0x320
/* Enable quasi-dynamic register programming outside reset */
#define UDDRC_SWCTRL_SW_DONE		BIT(0)

/* UDDRC Software Register Programming Control Status */
#define UDDRC_SWSTAT			0x324
#define UDDRC_SWSTAT_SW_DONE_ACK	BIT(0)	/* Register programming done */

/* UDDRC Port Status Register */
#define UDDRC_PSTAT			0x3FC
/* Read + writes outstanding transactions on all ports */
#define UDDRC_PSTAT_ALL_PORTS		0x1F001F

#define UDDRC_PCTRL_0			0x490	/* Port 0 Control Register */
#define UDDRC_PCTRL_1			0x540	/* Port 1 Control Register */
#define UDDRC_PCTRL_2			0x5F0	/* Port 2 Control Register */
#define UDDRC_PCTRL_3			0x6A0	/* Port 3 Control Register */
#define UDDRC_PCTRL_4			0x750	/* Port 4 Control Register */

#endif /* __SAMA7_DDR_H__ */
