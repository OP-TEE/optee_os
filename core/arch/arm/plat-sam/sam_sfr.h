/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, Bootlin
 */

#ifndef SAM_SFR_H
#define SAM_SFR_H

#include <stdbool.h>
#include <util.h>

/* OHCI INT Configuration Register */
#define AT91_SFR_OHCIICR	0x10
/* UTMI Clock Trimming Register */
#define AT91_SFR_UTMICKTRIM	0x30
/* Serial number 0 Register */
#define AT91_SFR_SN0		0x4c
/* Serial number 1 Register */
#define AT91_SFR_SN1		0x50
/* AIC Interrupt Redirection Register */
#define AT91_SFR_AICREDIR	0x54
/* L2 cache RAM used as an internal SRAM */
#define AT91_SFR_L2CC_HRAMC		0x58
/* I2SC Register */
#define AT91_SFR_I2SCLKSEL	0x90

/* Field definitions */
#define AT91_UTMICKTRIM_FREQ			GENMASK_32(1, 0)

#define AT91_OHCIICR_USB_SUSPEND		GENMASK_32(10, 8)

#define AT91_SFR_AICREDIR_XOR_KEY		0xb6d81c4d
#define AT91_SFR_AICREDIR_KEY_MASK		GENMASK_32(31, 1)

vaddr_t sam_sfr_base(void);

void atmel_sfr_set_usb_suspend(bool set);

#endif
