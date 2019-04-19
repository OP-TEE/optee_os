/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2017-2018 NXP
 *
 * @file    rng_regs.h
 *
 * @brief   Random Number Generator Registers.\n
 */
#ifndef __RNG_REGS_H__
#define __RNG_REGS_H__

/* Global includes */
#include <util.h>

/*
 * RNG Test Registers
 */
/* Miscellaneous Control */
#define TRNG_MCTL						0x0600
#define TRNG_MCTL_PRGM					BIT32(16)
#define TRNG_MCTL_ERR					BIT32(12)
#define TRNG_MCTL_ACC					BIT32(5)
#define BM_TRNG_MCTL_SAMP_MODE			SHIFT_U32(0x3, 0)
/* use raw data in both entropy shifter and statistical checker */
#define TRNG_MCTL_SAMP_MODE_RAW_ES_SC	SHIFT_U32(1, 0)

/* Seed Control */
#define TRNG_SDCTL					0x0610
#define BM_TRNG_SDCTL_ENT_DLY		SHIFT_U32(0xFFFF, 16)
#define GET_TRNG_SDCTL_ENT_DLY(val)	((val & BM_TRNG_SDCTL_ENT_DLY) >> 16)
#define TRNG_SDCTL_ENT_DLY(val)		SHIFT_U32((val & 0xFFFF), 16)

#ifdef CFG_MX6SX
/*
 * After experimentation on i.MX6SX, the minimal Delay value
 * allowing the RNG instantiation is 4800
 */
#define TRNG_SDCTL_ENT_DLY_MIN		(3200 + 1600)
#else
#define TRNG_SDCTL_ENT_DLY_MIN		3200
#endif
#define TRNG_SDCTL_ENT_DLY_MAX		12800

/* Frequency Count Minimum Limit */
#define TRNG_FRQMIN			0x0618
/* Frequency Count Maximum Limit */
#define TRNG_FRQMAX			0x061C

/*
 * RNG Registers
 */
/* Status */
#define RNG_STA				0x06C0

#define RNG_STA_SKVN		BIT32(30)
#define RNG_STA_IF1			BIT32(1)
#define RNG_STA_IF0			BIT32(0)

#endif /* __RNG_REGS_H__ */
