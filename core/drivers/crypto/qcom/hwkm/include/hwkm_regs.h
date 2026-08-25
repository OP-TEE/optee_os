/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc.
 *
 * HWKM register offsets and field masks.
 */

#ifndef __HWKM_REGS_H__
#define __HWKM_REGS_H__

#include <util.h>   /* BIT() and GENMASK_32(). */

/* SHARED_IPCAT_VERSION (HWKM_REGS_BASE + 0x0000U). */
/* IP Catalog version: [31:24] major, [23:16] minor, [15:0] step. */
#define HWKM_SHARED_IPCAT_VERSION	0x0000U

/* SHARED_KEY_POLICY_VERSION (HWKM_REGS_BASE + 0x0004U). */
/* Key-policy format version supported by this instance. */
#define HWKM_SHARED_KEY_POLICY_VERSION	0x0004U

/* SHARED_KEYTABLE_SIZE (HWKM_REGS_BASE + 0x000cU). */
/* Number of key slots in this instance's key table. */
#define HWKM_SHARED_KEYTABLE_SIZE	0x000cU

/* TZ_KM_CTL (HWKM_REGS_BASE + 0x1000U). */
#define HWKM_TZ_KM_CTL			0x1000U
/* Bit 0 - enable CRC validation on every command packet. */
#define HWKM_TZ_KM_CTL_CRC_CHECK_EN_SHIFT 0U
#define HWKM_TZ_KM_CTL_CRC_CHECK_EN \
	BIT(HWKM_TZ_KM_CTL_CRC_CHECK_EN_SHIFT)

/* TZ_KM_STATUS (HWKM_REGS_BASE + 0x1004U). */
#define HWKM_TZ_KM_STATUS		0x1004U
/*
 * Hardware BIST detected a fault in the key table or crypto logic.
 * If set, the instance must not be used; the driver treats this as
 * a fatal error.
 */
#define HWKM_TZ_KM_STATUS_BIST_ERROR_SHIFT 0xfU
#define HWKM_TZ_KM_STATUS_BIST_ERROR \
	BIT(HWKM_TZ_KM_STATUS_BIST_ERROR_SHIFT)
/*
 * Internal crypto-library self-test failed. Treated identically to
 * BIST_ERROR by the driver; either bit causes bist_failed to be set.
 */
#define HWKM_TZ_KM_STATUS_CRYPTO_LIB_BIST_ERROR_SHIFT 0xdU
#define HWKM_TZ_KM_STATUS_CRYPTO_LIB_BIST_ERROR \
	BIT(HWKM_TZ_KM_STATUS_CRYPTO_LIB_BIST_ERROR_SHIFT)

/* TPKEY_RECEIVE_CTL (HWKM_REGS_BASE + 0x101cU). */
#define HWKM_TZ_TPKEY_RECEIVE_CTL	0x101cU
/* Arm (1) or disarm (0) the slave for TPKEY reception. */
#define HWKM_TZ_TPKEY_RECEIVE_CTL_EN_SHIFT 0x8U
#define HWKM_TZ_TPKEY_RECEIVE_CTL_EN \
	BIT(HWKM_TZ_TPKEY_RECEIVE_CTL_EN_SHIFT)
/*
 * Destination key slot that will receive the incoming TPKEY [7:0].
 * Write CRYPTO_DEFAULT_TPKEY here before asserting EN.
 */
#define HWKM_TZ_TPKEY_RECEIVE_CTL_TPKEY_DKS	GENMASK_32(7, 0)

/* TZ_TPKEY_RECEIVE_STATUS (HWKM_REGS_BASE + 0x1020U). */
#define HWKM_TZ_TPKEY_RECEIVE_STATUS	0x1020U
/*
 * Set by hardware when the TPKEY has been written into TPKEY_DKS.
 * Poll this after SET_TPKEY, before disarming the slave.
 */
#define HWKM_TZ_TPKEY_RECEIVE_STATUS_DONE_SHIFT 0x8U
#define HWKM_TZ_TPKEY_RECEIVE_STATUS_DONE \
	BIT(HWKM_TZ_TPKEY_RECEIVE_STATUS_DONE_SHIFT)
/* Slot index where the TPKEY was stored (readback of TPKEY_DKS) [7:0]. */
#define HWKM_TZ_TPKEY_RECEIVE_STATUS_TPKEY_DKS	GENMASK_32(7, 0)

/* BANK0_KM_CTL (HWKM_REGS_BASE + 0x2000U). */
#define HWKM_BANK0_KM_CTL		0x2000U
/*
 * Enable the command FIFO for a new packet. Write 1 after clearing the
 * FIFO and ESR, before writing the first command word.
 */
#define HWKM_BANK0_KM_CTL_CMD_ENABLE_SHIFT 0U
#define HWKM_BANK0_KM_CTL_CMD_ENABLE \
	BIT(HWKM_BANK0_KM_CTL_CMD_ENABLE_SHIFT)
/*
 * Flush the command FIFO. Write 1 then 0 to reset. Read back: if still 1
 * after deassertion, the FIFO did not drain.
 */
#define HWKM_BANK0_KM_CTL_CMD_FIFO_CLEAR_SHIFT 0x1U
#define HWKM_BANK0_KM_CTL_CMD_FIFO_CLEAR \
	BIT(HWKM_BANK0_KM_CTL_CMD_FIFO_CLEAR_SHIFT)

/* BANK0_KM_STATUS (HWKM_REGS_BASE + 0x2004U). */
#define HWKM_BANK0_KM_STATUS		0x2004U
/*
 * Words of data available in the response FIFO [13:9].
 * Poll > 0 before reading each response word.
 */
#define HWKM_BANK0_KM_STATUS_RSP_AVAIL_DATA    GENMASK_32(13, 9)
/*
 * Words of free space in the command FIFO [18:14].
 * Poll > 0 before writing each command word.
 */
#define HWKM_BANK0_KM_STATUS_CMD_AVAIL_SPACE   GENMASK_32(18, 14)

/* KM_IRQ_STATUS (HWKM_REGS_BASE + 0x2008U). */
#define HWKM_BANK0_KM_IRQ_STATUS	0x2008U
/*
 * Set by hardware when the full command has been processed and the complete
 * response is in the RSP FIFO. If 0 after reading all expected response
 * words, more data remains -> HWKM_ERR_RSP_OVERFLOW.
 * Clear by writing 1 at the end of every successful transaction.
 */
#define HWKM_BANK0_KM_IRQ_STATUS_CMD_DONE_SHIFT 0x1U
#define HWKM_BANK0_KM_IRQ_STATUS_CMD_DONE \
	BIT(HWKM_BANK0_KM_IRQ_STATUS_CMD_DONE_SHIFT)
/*
 * Response FIFO full. May be spuriously set after reset (HW errata
 * QCTDD06252768). Clear unconditionally during init by writing 1.
 */
#define HWKM_BANK0_KM_IRQ_STATUS_RSP_FIFO_FULL_SHIFT 0x3U
#define HWKM_BANK0_KM_IRQ_STATUS_RSP_FIFO_FULL \
	BIT(HWKM_BANK0_KM_IRQ_STATUS_RSP_FIFO_FULL_SHIFT)

/*
 * BANK0_KM_ESR - Error status register (HWKM_REGS_BASE + 0x2010U).
 *
 * Each bit represents one error condition from the last command.
 * Clear pattern:
 *   io_write32_off(HWKM_REGS_BASE, HWKM_BANK0_KM_ESR,
 *                  io_read32_off(HWKM_REGS_BASE, HWKM_BANK0_KM_ESR))
 * Do this at the start of every transaction to acknowledge stale errors.
 */
#define HWKM_BANK0_KM_ESR		0x2010U

/*
 * BANK0_KM_CMD_FIFO - Command FIFO write port (HWKM_REGS_BASE + 0x201cU).
 *
 * Write one 32-bit command word per store after polling CMD_FIFO_AVAIL_SPACE.
 */
#define HWKM_BANK0_KM_CMD_FIFO		0x201cU

/*
 * BANK0_KM_RSP_FIFO - Response FIFO read port (HWKM_REGS_BASE + 0x205cU).
 *
 * Read one 32-bit response word per load after polling RSP_FIFO_AVAIL_DATA.
 */
#define HWKM_BANK0_KM_RSP_FIFO		0x205cU

/* Bank-Based Access Control (BBAC) bitmaps. */

#define HWKM_BANK0_AC			0x6000U
#define HWKM_BANK1_AC			0x7000U
#define HWKM_BANK2_AC			0x8000U
#define HWKM_BANK3_AC			0x9000U

#define HWKM_BANKn_AC_BBAC_0		0x0000U  /* slots 0-31.    */
#define HWKM_BANKn_AC_BBAC_1		0x0004U  /* slots 32-63.   */
#define HWKM_BANKn_AC_BBAC_2		0x0008U  /* slots 64-95.   */
#define HWKM_BANKn_AC_BBAC_3		0x000cU  /* slots 96-127.  */
#define HWKM_BANKn_AC_BBAC_4		0x0010U  /* slots 128-159. */

#endif /* __HWKM_REGS_H__ */
