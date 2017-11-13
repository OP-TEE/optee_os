/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2017-2018 NXP
 *
 */
#ifndef __RNG_REGS_H__
#define __RNG_REGS_H__

/*
 * RNG Test Registers
 */
/* Miscellaneous Control */
#define TRNG_MCTL			(0x0600)

#define BS_TRNG_MCTL_PRGM		(16)
#define BM_TRNG_MCTL_PRGM		(0x1 << BS_TRNG_MCTL_PRGM)
#define BS_TRNG_MCTL_TSTOP_OK		(13)
#define BM_TRNG_MCTL_TSTOP_OK		(0x1 << BS_TRNG_MCTL_TSTOP_OK)
#define BS_TRNG_MCTL_ERR		(12)
#define BM_TRNG_MCTL_ERR		(0x1 << BS_TRNG_MCTL_ERR)
#define BS_TRNG_MCTL_TEST_OUT		(11)
#define BM_TRNG_MCTL_TEST_OUT		(0x1 << BS_TRNG_MCTL_TEST_OUT)
#define BS_TRNG_MCTL_ENT_VAL		(10)
#define BM_TRNG_MCTL_ENT_VAL		(0x1 << BS_TRNG_MCTL_ENT_VAL)
#define BS_TRNG_MCTL_FCT_VAL		(9)
#define BM_TRNG_MCTL_FCT_VAL		(0x1 << BS_TRNG_MCTL_FCT_VAL)
#define BS_TRNG_MCTL_FCT_FAIL		(8)
#define BM_TRNG_MCTL_FCT_FAIL		(0x1 << BS_TRNG_MCTL_FCT_FAIL)
#define BS_TRNG_MCTL_FORCE_SYSCLK	(7)
#define BM_TRNG_MCTL_FORCE_SYSCLK	(0x1 << BS_TRNG_MCTL_FORCE_SYSCLK)
#define BS_TRNG_MCTL_RST_DEF		(6)
#define BM_TRNG_MCTL_RST_DEF		(0x1 << BS_TRNG_MCTL_RST_DEF)
#define BS_TRNG_MCTL_TRNG_ACC		(5)
#define BM_TRNG_MCTL_TRNG_ACC		(0x1 << BS_TRNG_MCTL_TRNG_ACC)
#define BS_TRNG_MCTL_CLK_OUT_EN		(4)
#define BM_TRNG_MCTL_CLK_OUT_EN		(0x1 << BS_TRNG_MCTL_CLK_OUT_EN)
#define BS_TRNG_MCTL_OSC_DIV		(2)
#define BM_TRNG_MCTL_OSC_DIV		(0x3 << BS_TRNG_MCTL_OSC_DIV)
#define BS_TRNG_MCTL_SAMP_MODE		(0)
#define BM_TRNG_MCTL_SAMP_MODE		(0x3 << BS_TRNG_MCTL_SAMP_MODE)

/* use von Neumann data in both entropy shifter and statistical checker */
#define	TRNG_MCTL_SAMP_MODE_VON_NEUMANN_ES_SC		\
				(0 << BS_TRNG_MCTL_SAMP_MODE)
/* use raw data in both entropy shifter and statistical checker */
#define TRNG_MCTL_SAMP_MODE_RAW_ES_SC			\
				(1 << BS_TRNG_MCTL_SAMP_MODE)
/* use von Neumann data in entropy shifter, raw data in statistical checker */
#define TRNG_MCTL_SAMP_MODE_VON_NEUMANN_ES_RAW_SC	\
				(2 << BS_TRNG_MCTL_SAMP_MODE)
/* invalid combination */
#define TRNG_MCTL_SAMP_MODE_INVALID			\
				(3 << BS_TRNG_MCTL_SAMP_MODE)

/* Statistical Check Miscellaneous */
#define TRNG_SCMISC			(0x0604)
/* Poker Range */
#define TRNG_PKRRNG			(0x0608)
/* Poker Maximum Limit */
#define TRNG_PKRMAX			(0x060C)
/* Poker Square Calculation Result */
#define TRNG_PKRSQ			(0x060C)
/* Seed Control */
#define TRNG_SDCTL			(0x0610)

#define BS_TRNG_SDCTL_ENT_DLY	(16)
#define BM_TRNG_SDCTL_ENT_DLY	(0xFFFF << BS_TRNG_SDCTL_ENT_DLY)
#define TRNG_SDCTL_ENT_DLY_MIN	(3200)
#define TRNG_SDCTL_ENT_DLY_MAX	(12800)

#define BS_TRNG_SDCTL_SAMP_SIZE	(0)
#define BM_TRNG_SDCTL_SAMP_SIZE	(0xFFFF << BS_TRNG_SDCTL_SAMP_SIZE)

/* Total Samples */
#define TRNG_TOTSAM		(0x0614)
/* Sparse Bit Limit */
#define TRNG_SBLIM		(0x0614)
/* Frequency Count Minimum Limit */
#define TRNG_FRQMIN		(0x0618)
/* Frequency Count */
#define TRNG_FRQCNT		(0x061C)
/* Frequency Count Maximum Limit */
#define TRNG_FRQMAX		(0x061C)
/* Statistical Check Monobit Limit */
#define TRNG_SCML		(0x0620)
/* Statistical Check Monobit Count */
#define TRNG_SCMC		(0x0620)

/* Statistical Check Run Length x */
#define TRNG_SCRx_SIZE		(0x4)
#define TRNG_SCR1L		(0x0624)
#define TRNG_SCR1C		(0x0624)
#define TRNG_SCRxL(idx)		(TRNG_SCR1L + (idx * TRNG_SCRx_SIZE))
#define TRNG_SCRxC(idx)		(TRNG_SCR1C + (idx * TRNG_SCRx_SIZE))

/* Status */
#define TRNG_STATUS		(0x063C)

/* Entropy Read x */
#define TRNG_ENTx_SIZE		(0x4)
#define TRNG_ENT0		(0x0640)
#define TRNG_ENTx(idx)		(TRNG_ENT0 + (idx * TRNG_ENTx_SIZE))

/* Statistical Check Poker Count x and (x + 1) */
#define TRNG_PKRCNTx_SIZE	(0x4)
#define TRNG_PKRCNT10		(0x0680)
#define TRNG_PKRCNTx(idx)	(TRNG_PKRCNT10 + (idx * TRNG_PKRCNTx_SIZE))

/*
 * RNG Registers
 */
/* Status */
#define RNG_STA			(0x06C0)

#define BS_RNG_STA_SKVT		(31)
#define BM_RNG_STA_SKVT		(0x1 << BS_RNG_STA_SKVT)
#define BS_RNG_STA_SKVN		(30)
#define BM_RNG_STA_SKVN		(0x1 << BS_RNG_STA_SKVN)
#define BS_RNG_STA_CE		(20)
#define BM_RNG_STA_CE		(0x1 << BS_RNG_STA_CE)
#define BS_RNG_STA_ERRCODE	(16)
#define BM_RNG_STA_ERRCODE	(0xF << BS_RNG_STA_ERRCODE)
#define BS_RNG_STA_TF1		(9)
#define BM_RNG_STA_TF1		(0x1 << BS_RNG_STA_TF1)
#define BS_RNG_STA_TF0		(8)
#define BM_RNG_STA_TF0		(0x1 << BS_RNG_STA_TF0)
#define BS_RNG_STA_PR1		(5)
#define BM_RNG_STA_PR1		(0x1 << BS_RNG_STA_PR1)
#define BS_RNG_STA_PR0		(4)
#define BM_RNG_STA_PR0		(0x1 << BS_RNG_STA_PR0)
#define BS_RNG_STA_IF1		(1)
#define BM_RNG_STA_IF1		(0x1 << BS_RNG_STA_IF1)
#define BS_RNG_STA_IF0		(0)
#define BM_RNG_STA_IF0		(0x1 << BS_RNG_STA_IF0)

/* State Handle 0 Reseed Interval */
#define RNG_INT0		(0x06D0)
/* State Handle 1 Reseed Interval */
#define RNG_INT1		(0x06D4)
/* Hash Control */
#define RNG_HCNTL		(0x06E0)
/* Hash Digest */
#define RNG_HDIG		(0x06E4)
/* Hash Buffer */
#define RNG_HBUF		(0x06E8)

#endif /* __RNG_REGS_H__ */
