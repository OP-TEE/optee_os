/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc.
 *
 * CRYPTO0 crypto engine register offsets and field masks.
 *
 * All offsets are relative to CRYPTO0_CRYPTO_REG_BASE, which is
 * CRYPTO0_CRYPTO_TOP_BASE (HWKM_CRYPTO0_BASE = 0x01dc0000) + 0x3a000.
 */

#ifndef __CE_REGS_H__
#define __CE_REGS_H__

#include <util.h>		/* BIT(), GENMASK_32() */
#include <utee_defines.h>	/* TEE_AES_BLOCK_SIZE */

/* Offset of CRYPTO_REG from CRYPTO0 top base (HWKM_CRYPTO0_BASE). */
#define CE_REG_OFFSET			0x3a000U

/*
 * DATA_INn - data-in FIFO write port (n = 0..3);
 * register mode only, write when DIN_RDY is set.
 */
#define CE_DATA_IN(n)			(0x010U + (n) * 4U)

/*
 * DATA_OUTn - data-out FIFO read port (n = 0..3);
 * register mode only, read when DOUT_RDY is set.
 */
#define CE_DATA_OUT(n)			(0x020U + (n) * 4U)
/* Number of data-in/data-out FIFO ports; port index wraps modulo this value. */
#define CE_FIFO_PORTS			4U

/* STATUS - engine status; reset 0. */
#define CE_STATUS			0x100U
/*
 * MAC validation for the last authenticated operation failed; read-only,
 * cleared by hardware when the next operation starts. Set by AES-GCM/CCM
 * decrypt when the supplied tag does not match the computed tag.
 */
#define CE_STATUS_MAC_FAILED		BIT(31)
/*
 * Bytes available in the data-out FIFO (max 16); never read more or an
 * error fires.
 */
#define CE_STATUS_DOUT_SIZE_AVAIL_SHIFT	26U
#define CE_STATUS_DOUT_SIZE_AVAIL	GENMASK_32(30, 26)
/*
 * Bytes free in the data-in FIFO (max 16); never write more or an error
 * fires.
 */
#define CE_STATUS_DIN_SIZE_AVAIL_SHIFT	21U
#define CE_STATUS_DIN_SIZE_AVAIL	GENMASK_32(25, 21)
/* Access to a protected register was attempted; W0C. */
#define CE_STATUS_ACCESS_VIOL		BIT(19)
/* Encryption block is active. */
#define CE_STATUS_ENCR_BUSY		BIT(9)
/* Authentication block is active. */
#define CE_STATUS_AUTH_BUSY		BIT(8)
/* Interrupt flag: asserted when any of bits [19:15] cause errors; W0C. */
#define CE_STATUS_ERR_INTR		BIT(4)
/* Data may be read from DATA_OUT. */
#define CE_STATUS_DOUT_RDY		BIT(3)
/* Data may be written to DATA_IN. */
#define CE_STATUS_DIN_RDY		BIT(2)
/* Operation complete; cleared by writing GOPROC.GO. */
#define CE_STATUS_OPERATION_DONE	BIT(1)
/* Logical OR of bits [19:15]; W0C. */
#define CE_STATUS_SW_ERR		BIT(0)

/* Status2 - extended error status; reset 0. */
#define CE_STATUS2			0x104U
/* HW BIST detected a fault; operation result must not be trusted. */
#define CE_STATUS2_BIST_ERROR		BIT(31)
/* Key equality error (XTS key1==key2, or TDES keys equal); op was skipped. */
#define CE_STATUS2_KEY_ERR		BIT(29)

/* ENGINES_AVAIL - read-only; indicates which algorithm engines are present. */
#define CE_ENGINES_AVAIL		0x108U
/* AES engine available for encryption; must be set before registering. */
#define CE_ENGINES_AVAIL_ENCR_AES_SEL	BIT(0)

/*
 * SEG_SIZE - total segment bytes to process after GO;
 * must be >= ENCR_SEG_START + ENCR_SEG_SIZE.
 */
#define CE_SEG_SIZE			0x110U

/*
 * GOPROC - write-only; always last register written;
 * writing GO clears OPERATION_DONE.
 */
#define CE_GOPROC			0x120U
/* Signal configuration complete; engine proceeds. */
#define CE_GOPROC_GO			BIT(0)

/* ENCR_SEG_CFG - encryption engine configuration. */
#define CE_ENCR_SEG_CFG			0x200U
/* 1 = encrypt (forward transform), 0 = decrypt. */
#define CE_ENCR_SEG_CFG_ENCODE		BIT(10)
/* ENCR_MODE [9:6]: 0=ECB, 1=CBC, 2=CTR, 3=XTS, 4=CCM, 6=GCM. */
#define CE_ENCR_SEG_CFG_MODE_SHIFT	6U
#define CE_ENCR_SEG_CFG_MODE_MASK	GENMASK_32(9, 6)
#define CE_ENCR_MODE_ECB		0U
#define CE_ENCR_MODE_CBC		1U
#define CE_ENCR_MODE_GCM		6U
/* LAST [13]: last segment in CCM/GCM operation; triggers tag computation. */
#define CE_ENCR_SEG_CFG_LAST		BIT(13)
/* ENCR_KEY_SZ [5:3]: AES key size encoding; 0=128-bit, 2=256-bit. */
#define CE_ENCR_SEG_CFG_KEY_SZ_SHIFT	3U
#define CE_ENCR_SEG_CFG_KEY_SZ_MASK	GENMASK_32(5, 3)
#define CE_KEY_SZ_AES128		0U
#define CE_KEY_SZ_AES256		2U
/* ENCR_ALG [2:0]: 0=NONE, 1=DES, 2=AES, 3=SM4. */
#define CE_ENCR_SEG_CFG_ALG_SHIFT	0U
#define CE_ENCR_SEG_CFG_ALG_MASK	GENMASK_32(2, 0)
#define CE_ENCR_ALG_AES			2U

/*
 * ENCR_SEG_SIZE - bytes for the encryption engine;
 * starts at ENCR_SEG_START; 0 is pass-through.
 */
#define CE_ENCR_SEG_SIZE		0x204U

/*
 * ENCR_SEG_START - bytes to skip before encryption begins;
 * prior bytes pass through unmodified.
 */
#define CE_ENCR_SEG_START		0x208U

/*
 * ENCR_CNTR_IVn - IV / initial counter (n=0..3);
 *                 IV0 = [127:96], IV3 = [31:0]; reset 0.
 * ECB: unused, written 0.
 * CBC: IV per segment, HW updates after completion.
 * GCM: J0+1 (pre-counter block incremented once); only IV3 (bits[31:0])
 *      increments per block; IV0..2 are frozen by ENCR_CNTR_MASKn=0.
 */
#define CE_ENCR_IV0		0x20cU
#define CE_ENCR_IV1		0x210U
#define CE_ENCR_IV2		0x214U
#define CE_ENCR_IV3		0x218U

/*
 * ENCR_CNTR_MASKn - counter increment mask paired with IVn;
 *                   bits=1 increment, bits=0 hold fixed.
 */
#define CE_ENCR_CNTR_MASK3	0x21cU
#define CE_ENCR_CNTR_MASK2	0x234U
#define CE_ENCR_CNTR_MASK1	0x238U
#define CE_ENCR_CNTR_MASK0	0x23cU

/* ENCR_CCM_INIT_CNTRn - CCM/GCM initial counter J0 (n=0..3, step 4). */
#define CE_ENCR_CCM_INIT_CNTR(n)	(0x220U + (n) * 4U)

/*
 * AUTH_SEG_CFG - authentication engine configuration; reset 0.
 * Write 0 for cipher-only ops.
 */
#define CE_AUTH_SEG_CFG			0x300U
/* AUTH_ALG [2:0]: 0=NONE, 2=AES. */
#define CE_AUTH_SEG_CFG_ALG_SHIFT	0U
#define CE_AUTH_SEG_CFG_ALG_MASK	GENMASK_32(2, 0)
#define CE_AUTH_ALG_AES			2U
/* AUTH_KEY_SZ [5:3]: same encoding as ENCR_KEY_SZ; 0=AES-128, 2=AES-256. */
#define CE_AUTH_SEG_CFG_KEY_SZ_SHIFT	3U
#define CE_AUTH_SEG_CFG_KEY_SZ_MASK	GENMASK_32(5, 3)
/* AUTH_MODE [8:6]: 0=CBC-MAC (CCM), 2=GHASH (GCM). */
#define CE_AUTH_SEG_CFG_MODE_SHIFT	6U
#define CE_AUTH_SEG_CFG_MODE_MASK	GENMASK_32(8, 6)
#define CE_AUTH_MODE_GCM		2U
/* AUTH_SIZE [13:9]: MAC output size in bytes minus 1. */
#define CE_AUTH_SEG_CFG_SIZE_SHIFT	9U
#define CE_AUTH_SEG_CFG_SIZE_MASK	GENMASK_32(13, 9)
/* AUTH_POS [15:14]: 0 = auth before cipher, 1 = auth after cipher. */
#define CE_AUTH_SEG_CFG_POS_AFTER	BIT(14)
/* LAST [16]: last segment; triggers MAC finalisation. */
#define CE_AUTH_SEG_CFG_LAST		BIT(16)
/* FIRST [17]: first segment. */
#define CE_AUTH_SEG_CFG_FIRST		BIT(17)

/* AUTH_SEG_SIZE - bytes covered by the auth engine; reset 0. */
#define CE_AUTH_SEG_SIZE		0x304U

/* AUTH_SEG_START - byte offset within segment where auth begins; reset 0. */
#define CE_AUTH_SEG_START		0x308U

/* AUTH_IVn - authentication IV / GHASH accumulator (n=0..15, step 4). */
#define CE_AUTH_IV(n)			(0x310U + (n) * 4U)
#define CE_AUTH_IV_WORDS		16U

/*
 * AUTH_INFO_NONCEn - named for CCM where this holds the formatted nonce;
 * for GCM it carries the length block {len(AAD) || len(P)} in bits
 * (n=0..3, step 4).
 */
#define CE_AUTH_INFO_NONCE(n)		(0x350U + (n) * 4U)

/* AUTH_BYTECNTn - authentication byte/bit counters (n=0..3). */
#define CE_AUTH_BYTECNT0		0x390U
#define CE_AUTH_BYTECNT1		0x394U
#define CE_AUTH_BYTECNT2		0x398U
#define CE_AUTH_BYTECNT3		0x39cU

/* AUTH_KEYn - authentication key words (n=0..15, step 4); write-only. */
#define CE_AUTH_KEY(n)			(0x3040U + (n) * 4U)

/* CONFIG - core configuration; reset 0x100E001F. */
#define CE_CONFIG			0x400U
/* Make DATA_IN/OUT, IV, and KEY registers little-endian. */
#define CE_CONFIG_LITTLE_ENDIAN_MODE	BIT(9)
/* Active-low BAM/DMA enable; 1 = BAM disabled (register mode). */
#define CE_CONFIG_HIGH_SPD_DATA_EN_N	BIT(4)
/* 1 = suppress data-out interrupt. */
#define CE_CONFIG_MASK_DOUT_INTR	BIT(3)
/* 1 = suppress data-in interrupt. */
#define CE_CONFIG_MASK_DIN_INTR		BIT(2)
/* 1 = suppress operation-done interrupt. */
#define CE_CONFIG_MASK_OP_DONE_INTR	BIT(1)

#define CE_CONFIG_DEFAULT		(CE_CONFIG_LITTLE_ENDIAN_MODE  | \
					 CE_CONFIG_HIGH_SPD_DATA_EN_N  | \
					 CE_CONFIG_MASK_DOUT_INTR      | \
					 CE_CONFIG_MASK_DIN_INTR       | \
					 CE_CONFIG_MASK_OP_DONE_INTR)

/*
 * ENCR_KEYn - AES key words (n=0..7, step 4); write-only; word 0 = MSB.
 * AES-128: words 0..3; words 4..7 must be 0. AES-256: all 8 words.
 */
#define CE_ENCR_KEY(n)			(0x3000U + (n) * 4U)

#define CE_MAX_KEY_WORDS		8U
#define CE_MAX_AUTH_KEY_WORDS		16U
/* 128-bit IV = four 32-bit words. */
#define CE_IV_WORDS			4U
/* Byte size of one CE register word. */
#define CE_WORD_SIZE			4U

#endif /* __CE_REGS_H__ */
