// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018-2019 NXP
 *
 * @file    hal_rng.c
 *
 * @brief   CAAM Random Number Generator Hardware Abstration Layer.\n
 *          Implementation of primitives to access HW
 */

/* Local includes */
#include "caam_io.h"
#include "caam_status.h"

/* Hal includes */
#include "hal_rng.h"

/* Register includes */
#include "rng_regs.h"
#include "version_regs.h"

/**
 * @brief   Returns if all RNG State Handler already instantiated or not
 *
 * @param[in] baseaddr  RNG Base Address
 *
 * @retval  true  RNG is instantiated
 * @retval  false RNG is not instantiated
 */
bool hal_rng_instantiated(vaddr_t baseaddr)
{
	uint32_t chaVid_ls;
	uint32_t nbSH;
	uint32_t status;

	chaVid_ls = io_caam_read32(baseaddr + CHAVID_LS);

	/* RNG version < 4 and RNG state handle is already instantiated */
	if (GET_CHAVID_LS_RNGVID(chaVid_ls) < 4)
		return true;

	/* Get the Number of State Handles */
	nbSH = hal_rng_get_nbSH(baseaddr);

	/* Read the RNG Status and checks if all channels are instantiatied */
	status = hal_rng_get_statusSH(baseaddr);

	if (status != (uint32_t)((1 << nbSH) - 1))
		return false;

	return true;
}

/**
 * @brief   Returns the number of RNG State Handle
 *
 * @param[in] baseaddr  RNG Base Address
 *
 * @retval  Number of RNG SH
 */
uint32_t hal_rng_get_nbSH(vaddr_t baseaddr)
{
	uint32_t reg;

	reg = io_caam_read32(baseaddr + CTPR_MS);

	return GET_CTPR_MS_RNG_I(reg);
}

/**
 * @brief   Returns the RNG Status State Handle
 *
 * @param[in] baseaddr  RNG Base Address
 *
 * @retval  RNG State Handles status
 */
uint32_t hal_rng_get_statusSH(vaddr_t baseaddr)
{
	uint32_t reg;

	reg = io_caam_read32(baseaddr + RNG_STA);

	reg &= RNG_STA_IF1 | RNG_STA_IF0;

	return reg;
}

/**
 * @brief   Returns the RNG Status Key Loade
 *
 * @param[in] baseaddr  RNG Base Address
 *
 * @retval  true   Secure Keys are loaded
 * @retval  false  Secure Keys not are loaded
 */
bool hal_rng_key_loaded(vaddr_t baseaddr)
{
	uint32_t reg;

	reg = io_caam_read32(baseaddr + RNG_STA);

	return (((reg & RNG_STA_SKVN) == RNG_STA_SKVN) ? true : false);
}

/**
 * @brief   Configures the RNG entropy delay
 *
 * @param[in] baseaddr   RNG Base Address
 * @param[in] inc_delay  Entropy Delay incrementation
 *
 * @retval  CAAM_NO_ERROR      Success
 * @retval  CAAM_OUT_OF_BOUND  Value is out of boundary
 */
enum CAAM_Status hal_rng_kick(vaddr_t baseaddr, uint32_t inc_delay)
{
	uint32_t val;
	uint32_t ent_delay = TRNG_SDCTL_ENT_DLY_MIN + inc_delay;

	if (ent_delay > TRNG_SDCTL_ENT_DLY_MAX)
		return CAAM_OUT_OF_BOUND;

	/* Put RNG in program mode
	 * Setting both RTMCTL:PRGM and RTMCTL:TRNG_ACC causes TRNG to
	 * properly invalidate the entropy in the entropy register and
	 * force re-generation
	 */
	io_mask32(baseaddr + TRNG_MCTL,
			(TRNG_MCTL_PRGM | TRNG_MCTL_ACC),
			(TRNG_MCTL_PRGM | TRNG_MCTL_ACC));

	/* Configure the RNG Entropy Delay
	 * Performance-wise, it does not make sense to
	 * set the delay to a value that is lower
	 * than the last one that worked (i.e. the state handles
	 * were instantiated properly. Thus, instead of wasting
	 * time trying to set the values controlling the sample
	 * frequency, the function simply returns.
	 */
	val = io_caam_read32(baseaddr + TRNG_SDCTL);
	val = GET_TRNG_SDCTL_ENT_DLY(val);

	if (ent_delay < val) {
		/*
		 * In this case do the programmation anyway because on some
		 * device the other registers value can be wrong.
		 */
		ent_delay = val;
	}

	val = io_caam_read32(baseaddr + TRNG_SDCTL);
	val &= ~BM_TRNG_SDCTL_ENT_DLY;
	val |= TRNG_SDCTL_ENT_DLY(ent_delay);
	io_caam_write32(baseaddr + TRNG_SDCTL, val);

	/* min. freq. count, equal to 1/4 of the entropy sample length */
	io_caam_write32(baseaddr + TRNG_FRQMIN, ent_delay >> 2);

	/* max. freq. count, equal to 16 times the entropy sample length */
	io_caam_write32(baseaddr + TRNG_FRQMAX, ent_delay << 4);

	val = io_caam_read32(baseaddr + TRNG_MCTL);
	/*
	 * Select raw sampling in both entropy shifter
	 * and statistical checker
	 */
	val &= ~BM_TRNG_MCTL_SAMP_MODE;
	val |= TRNG_MCTL_SAMP_MODE_RAW_ES_SC;
	/* Put RNG4 into run mode with handling CAAM/RNG4-TRNG Errata */
	val &= ~(TRNG_MCTL_PRGM | TRNG_MCTL_ACC);
	io_caam_write32(baseaddr + TRNG_MCTL, val);

	/* Clear the ERR bit in RTMCTL if set. The TRNG error can occur when
	 * the RNG clock is not within 1/2x to 8x the system clock.
	 * This error is possible if ROM code does not initialize the system
	 * PLLs immediately after PoR.
	 */
	val = io_caam_read32(baseaddr + TRNG_MCTL) | TRNG_MCTL_ERR;
	io_caam_write32(baseaddr + TRNG_MCTL, val);

	return CAAM_NO_ERROR;
}

