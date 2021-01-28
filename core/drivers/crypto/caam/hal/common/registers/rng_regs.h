/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2017-2019 NXP
 *
 * Brief   Random Number Generator Registers.
 */
#ifndef __RNG_REGS_H__
#define __RNG_REGS_H__

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
/* Use raw data in both entropy shifter and statistical checker */
#define TRNG_MCTL_SAMP_MODE_RAW_ES_SC	SHIFT_U32(1, 0)

/* Seed Control */
#define TRNG_SDCTL			0x0610
#define BM_TRNG_SDCTL_ENT_DLY		SHIFT_U32(0xFFFF, 16)
#define GET_TRNG_SDCTL_ENT_DLY(val)	(((val) & BM_TRNG_SDCTL_ENT_DLY) >> 16)
#define TRNG_SDCTL_ENT_DLY(val)		SHIFT_U32(((val) & 0xFFFF), 16)
#define TRNG_SDCTL_SAMP_SIZE(val)	((val) & 0xFFFF)

#define TRNG_SDCTL_ENT_DLY_MIN		3200
#define TRNG_SDCTL_ENT_DLY_MAX		12800

/* Frequency Count Minimum Limit */
#define TRNG_FRQMIN			0x0618
/* Frequency Count Maximum Limit */
#define TRNG_FRQMAX			0x061C

/* Statistical Check Miscellaneous */
#define TRNG_RTSCMISC		    0x0604
#define BM_TRNG_RTSCMISC_RTY_CNT    SHIFT_U32(0xF, 16)
#define TRNG_RTSCMISC_RTY_CNT(val)  SHIFT_U32(((val) & (0xF)), 16)
#define BM_TRNG_RTSCMISC_LRUN_MAX   SHIFT_U32(0xFF, 0)
#define TRNG_RTSCMISC_LRUN_MAX(val) SHIFT_U32(((val) & (0xFF)), 0)

/* Poker Range */
#define TRNG_RTPKRRNG		   0x0608
#define BM_TRNG_RTPKRRNG_PKR_RNG   SHIFT_U32(0xFFFF, 0)
#define TRNG_RTPKRRNG_PKR_RNG(val) SHIFT_U32(((val) & (0xFFFF)), 0)

/* Poker Maximum Limit */
#define TRNG_RTPKRMAX		   0x060C
#define BM_TRNG_RTPKRMAX_PKR_MAX   SHIFT_U32(0xFFFFFF, 0)
#define TRNG_RTPKRMAX_PKR_MAX(val) SHIFT_U32(((val) & (0xFFFFFF)), 0)

/* Statistical Check Monobit Limit */
#define TRNG_RTSCML		  0x0620
#define BM_TRNG_RTSCML_MONO_RNG	  SHIFT_U32(0xFFFF, 16)
#define TRNG_RTSCML_MONO_RNG(val) SHIFT_U32(((val) & (0xFFFF)), 16)
#define BM_TRNG_RTSCML_MONO_MAX	  SHIFT_U32(0xFFFF, 0)
#define TRNG_RTSCML_MONO_MAX(val) SHIFT_U32(((val) & (0xFFFF)), 0)

/* Statistical Check Run Length 1 Limit */
#define TRNG_RTSCR1L		   0x0624
#define BM_TRNG_RTSCR1L_RUN1_RNG   SHIFT_U32(0x7FFF, 16)
#define TRNG_RTSCR1L_RUN1_RNG(val) SHIFT_U32(((val) & (0x7FFF)), 16)
#define BM_TRNG_RTSCR1L_RUN1_MAX   SHIFT_U32(0x7FFF, 0)
#define TRNG_RTSCR1L_RUN1_MAX(val) SHIFT_U32(((val) & (0x7FFF)), 0)

/* Statistical Check Run Length 2 Limit */
#define TRNG_RTSCR2L		   0x0628
#define BM_TRNG_RTSCR2L_RUN2_RNG   SHIFT_U32(0x3FFF, 16)
#define TRNG_RTSCR2L_RUN2_RNG(val) SHIFT_U32(((val) & (0x3FFF)), 16)
#define BM_TRNG_RTSCR2L_RUN2_MAX   SHIFT_U32(0x3FFF, 0)
#define TRNG_RTSCR2L_RUN2_MAX(val) SHIFT_U32(((val) & (0x3FFF)), 0)

/* Statistical Check Run Length 3 Limit */
#define TRNG_RTSCR3L		   0x062C
#define BM_TRNG_RTSCR3L_RUN3_RNG   SHIFT_U32(0x1FFF, 16)
#define TRNG_RTSCR3L_RUN3_RNG(val) SHIFT_U32(((val) & (0x1FFF)), 16)
#define BM_TRNG_RTSCR3L_RUN3_MAX   SHIFT_U32(0x1FFF, 0)
#define TRNG_RTSCR3L_RUN3_MAX(val) SHIFT_U32(((val) & (0x1FFF)), 0)

/* Statistical Check Run Length 4 Limit */
#define TRNG_RTSCR4L		   0x0630
#define BM_TRNG_RTSCR4L_RUN4_RNG   SHIFT_U32(0xFFF, 16)
#define TRNG_RTSCR4L_RUN4_RNG(val) SHIFT_U32(((val) & (0xFFF)), 16)
#define BM_TRNG_RTSCR4L_RUN4_MAX   SHIFT_U32(0xFFF, 0)
#define TRNG_RTSCR4L_RUN4_MAX(val) SHIFT_U32(((val) & (0xFFF)), 0)

/* Statistical Check Run Length 5 Limit */
#define TRNG_RTSCR5L		   0x0634
#define BM_TRNG_RTSCR5L_RUN5_RNG   SHIFT_U32(0x7FF, 16)
#define TRNG_RTSCR5L_RUN5_RNG(val) SHIFT_U32(((val) & (0x7FF)), 16)
#define BM_TRNG_RTSCR5L_RUN5_MAX   SHIFT_U32(0x7FF, 0)
#define TRNG_RTSCR5L_RUN5_MAX(val) SHIFT_U32(((val) & (0x7FF)), 0)

/* Statistical Check Run Length 6+ Limit */
#define TRNG_RTSCR6PL		     0x0638
#define BM_TRNG_RTSCR6PL_RUN6P_RNG   SHIFT_U32(0x7FF, 16)
#define TRNG_RTSCR6PL_RUN6P_RNG(val) SHIFT_U32(((val) & (0x7FF)), 16)
#define BM_TRNG_RTSCR6PL_RUN6P_MAX   SHIFT_U32(0x7FF, 0)
#define TRNG_RTSCR6PL_RUN6P_MAX(val) SHIFT_U32(((val) & (0x7FF)), 0)

/*
 * RNG Registers
 */
/* Status */
#define RNG_STA				0x06C0

#define RNG_STA_SKVN		BIT32(30)
#define RNG_STA_IF1			BIT32(1)
#define RNG_STA_IF0			BIT32(0)

#endif /* __RNG_REGS_H__ */
