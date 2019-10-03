// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2019 NXP
 *
 * Brief   CAAM Random Number Generator Hardware Abstration Layer.
 *         Implementation of primitives to access HW.
 */
#include <caam_hal_rng.h>
#include <caam_io.h>
#include <caam_status.h>
#include <registers/rng_regs.h>
#include <registers/version_regs.h>

bool caam_hal_rng_instantiated(vaddr_t baseaddr)
{
	uint32_t chavid_ls = 0;
	uint32_t nb_sh = 0;
	uint32_t status = 0;

	chavid_ls = io_caam_read32(baseaddr + CHAVID_LS);

	/* RNG version < 4 and RNG state handle is already instantiated */
	if (GET_CHAVID_LS_RNGVID(chavid_ls) < 4)
		return true;

	/* Get the Number of State Handles */
	nb_sh = caam_hal_rng_get_nb_sh(baseaddr);

	/* Read the RNG Status and checks if all channels are instantiatied */
	status = caam_hal_rng_get_sh_status(baseaddr);

	if (status != GENMASK_32(nb_sh - 1, 0))
		return false;

	return true;
}

uint32_t caam_hal_rng_get_nb_sh(vaddr_t baseaddr)
{
	uint32_t reg = 0;

	reg = io_caam_read32(baseaddr + CTPR_MS);

	return GET_CTPR_MS_RNG_I(reg);
}

uint32_t caam_hal_rng_get_sh_status(vaddr_t baseaddr)
{
	return io_caam_read32(baseaddr + RNG_STA) & (RNG_STA_IF1 | RNG_STA_IF0);
}

bool caam_hal_rng_key_loaded(vaddr_t baseaddr)
{
	return io_caam_read32(baseaddr + RNG_STA) & RNG_STA_SKVN;
}

enum caam_status caam_hal_rng_kick(vaddr_t baseaddr, uint32_t inc_delay)
{
	uint32_t val = 0;
	uint32_t ent_delay = TRNG_SDCTL_ENT_DLY_MIN + inc_delay;

	if (ent_delay > TRNG_SDCTL_ENT_DLY_MAX)
		return CAAM_OUT_OF_BOUND;

	/*
	 * Switch RNG in program mode
	 * Setting both RTMCTL:PRGM and RTMCTL:TRNG_ACC causes TRNG to
	 * properly invalidate the entropy in the entropy register and
	 * force re-generation
	 */
	io_setbits32(baseaddr + TRNG_MCTL, TRNG_MCTL_PRGM | TRNG_MCTL_ACC);

	/*
	 * Configure the RNG Entropy Delay
	 * Performance-wise, it does not make sense to
	 * set the delay to a value that is lower
	 * than the last one that worked (i.e. the state handles
	 * were instantiated correctly). Thus, instead of wasting
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

	/*
	 * Clear the ERR bit in RTMCTL if set. The TRNG error can occur when
	 * the RNG clock is not within 1/2x to 8x the system clock.
	 * This error is possible if ROM code does not initialize the system
	 * PLLs immediately after PoR.
	 */
	io_setbits32(baseaddr + TRNG_MCTL, TRNG_MCTL_ERR);

	return CAAM_NO_ERROR;
}
