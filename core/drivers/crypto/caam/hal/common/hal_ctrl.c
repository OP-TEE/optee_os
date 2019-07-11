// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018-2019 NXP
 *
 * @file    hal_ctrl.c
 *
 * @brief   CAAM Controller Hardware Abstration Layer.\n
 *          Implementation of primitives to access HW
 */

/* Global includes */
/* Platform includes */
#ifndef CFG_LS
#include <imx.h>
#endif

/* Library Crypto includes */
#ifdef CFG_CRYPTO_HASH_HW
#include <drvcrypt_hash.h>
#endif

/* Local includes */
#include "caam_io.h"

/* Hal includes */
#include "hal_ctrl.h"

/* Register includes */
#include "ctrl_regs.h"

/* Register includes */
#include "version_regs.h"

/**
 * @brief   Returns the number of Job Ring supported
 *
 * @param[in] baseaddr  Controller base address
 *
 * @retval  The number of Job Ring in HW
 */
uint8_t hal_ctrl_jrnum(vaddr_t baseaddr)
{
	uint32_t val;

	val = io_caam_read32(baseaddr + CHANUM_MS);

	return GET_CHANUM_MS_JRNUM(val);
}

#ifdef CFG_CRYPTO_HASH_HW
/**
 * @brief   Returns the Maximum Hash supported
 *
 * @param[in] baseaddr  Controller base address
 *
 * @retval  Maximum Hash Id supported
 * @retval  (-1) if hash is not supported
 */
int hal_ctrl_hash_limit(vaddr_t baseaddr)
{
	uint32_t val;

	/* Read the number of instance */
	val = io_caam_read32(baseaddr + CHANUM_LS);

	if (GET_CHANUM_LS_MDNUM(val)) {
		/* Hashing is supported */
		val = io_caam_read32(baseaddr + CHAVID_LS);
		val &= BM_CHAVID_LS_MDVID;
		if (val == CHAVID_LS_MDVID_LP256)
			return HASH_SHA256;

		return HASH_SHA512;
	}

	return (-1);
}

/**
 * @brief   Returns if the HW support the split key operation.
 *          Split key is supported if CAAM Version is > 3
 *
 * @param[in] baseaddr  Controller base address
 *
 * @retval  true  if split key is supported
 * @retval  false otherwise
 */
bool hal_ctrl_splitkey(vaddr_t baseaddr)
{
	uint32_t val;

	/* Read the number of instance */
	val = io_caam_read32(baseaddr + CAAMVID_MS);

	if (GET_CAAMVID_MS_MAJ_REV(val) < 3)
		return false;

	return true;
}
#endif // CFG_CRYPTO_HASH_HW

/**
 * @brief   Returns the CAAM Era
 *
 * @param[in] baseaddr  Controller base address
 *
 * @retval  Era version
 */
uint8_t hal_ctrl_caam_era(vaddr_t baseaddr)
{
	uint32_t val;

	/* Read the number of instance */
	val = io_caam_read32(baseaddr + CCBVID);

	return GET_CCBVID_CAAM_ERA(val);
}
